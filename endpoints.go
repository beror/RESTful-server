package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"

	"time"
)

type PLang struct {
	ID   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type User struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func GetPLanguagesEndpoint(w http.ResponseWriter, req *http.Request) {
	username := req.Context().Value("props").(jwt.MapClaims)["username"]

	fmt.Println("GET", username, time.Now(), "\n")

	rows, err := db.Query("SELECT PLangID, programming_languages.Name FROM programming_languages, users, users_programming_languages WHERE users.Username = ? AND users.UserID = users_programming_languages.User AND programming_languages.PLangID = users_programming_languages.PLang", username)
	if err != nil {
		fmt.Println("Error querying database:", err, "\n")
	}

	pLangs := []PLang{}
	var pLangID int
	var pLangName string

	for rows.Next() {
		rows.Scan(&pLangID, &pLangName)
		pLangs = append(pLangs, PLang{ID: pLangID, Name: pLangName})
	}

	json.NewEncoder(w).Encode(&pLangs)
}

func AddPLanguageEndpoint(w http.ResponseWriter, req *http.Request) {
	var pLang PLang
	json.NewDecoder(req.Body).Decode(&pLang)

	username := req.Context().Value("props").(jwt.MapClaims)["username"]

	fmt.Println("POST", username, pLang.Name, time.Now(), "\n")

	insertRes, errExec := db.Exec("INSERT INTO users_programming_languages (User, PLang) SELECT UserID, PLangID FROM users, programming_languages WHERE Username = ? AND Name = ?", username, pLang.Name)
	if errExec != nil {
		fmt.Println("Error querying database:", errExec)
	}

	rowsAffected, _ := insertRes.RowsAffected()

	if rowsAffected == 0 {
		insertRes, errExec = db.Exec("INSERT INTO programming_languages (Name) VALUES (?)", pLang.Name)
		if errExec != nil {
			fmt.Println("Error querying database:", errExec)
		}
		insertedLangID, _ := insertRes.LastInsertId()
		_, errExec = db.Exec("INSERT INTO users_programming_languages (User, PLang) SELECT UserID, PLangID FROM users, programming_languages WHERE Username = ? AND PLangID = ?", username, insertedLangID)
		if errExec != nil {
			fmt.Println("Error querying database:", errExec)
		}
	}

	GetPLanguagesEndpoint(w, req)
}

func EditPLanguageEndpoint(w http.ResponseWriter, req *http.Request) {
	newAndOldPLangs := struct {
		NameToEdit string
		NewName    string
	}{}
	json.NewDecoder(req.Body).Decode(&newAndOldPLangs)

	username := req.Context().Value("props").(jwt.MapClaims)["username"]

	fmt.Println("PUT", username, newAndOldPLangs.NameToEdit, newAndOldPLangs.NewName, "\n")

	_, err := db.Exec("UPDATE users_programming_languages SET PLang = (SELECT PLangID FROM programming_languages WHERE Name = ?) WHERE User = (SELECT UserID FROM users WHERE Username = ?) AND PLang = (SELECT PLangID FROM programming_languages WHERE Name = ?)", newAndOldPLangs.NewName, username, newAndOldPLangs.NameToEdit)
	if err == nil {
		w.WriteHeader(http.StatusOK)
	} else {
		fmt.Println("Error querying database:", err)
	}
}

func DeletePLanguageEndpoint(w http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)

	username := req.Context().Value("props").(jwt.MapClaims)["username"]

	fmt.Println("DELETE", username, params["id"], time.Now(), "\n")

	db.Exec("DELETE FROM users_programming_languages WHERE User = (SELECT UserID FROM users WHERE Username = ?) AND PLang = ?", username, params["id"])

	GetPLanguagesEndpoint(w, req)
}

func LoginEndpoint(w http.ResponseWriter, req *http.Request) {
	var user User
	json.NewDecoder(req.Body).Decode(&user)

	fmt.Println("Login attempt:", user.Username, user.Password)

	rows, errDB := db.Query("SELECT Username, Password FROM programming_languages.users WHERE Username = ? AND Password = ?", user.Username, user.Password)
	if errDB != nil {
		fmt.Println("Error querying database")
	}

	user.Username = ""
	user.Password = ""

	for rows.Next() {
		rows.Scan(&user.Username, &user.Password)
	}

	if user.Username != "" && user.Password != "" {
		fmt.Println("Found the user in the database")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username":            user.Username, // TODO: should send user's id instead?
			"userPermissionLevel": "0",
		})
		createdJWT, err := token.SignedString(secret)
		if err != nil {
			fmt.Println("Couldn't sign token")
			http.Error(w, "Couldn't create JWT token", http.StatusInternalServerError)
			return
		} else {
			fmt.Printf("JWT for %v: %v\n\n", user.Username, createdJWT)
			w.Header().Set("Authorization", "Bearer "+createdJWT)
		}
	} else {
		fmt.Println("No such user found\n")
	}
}

func SignupEndpoint(w http.ResponseWriter, req *http.Request) {
	var user User
	json.NewDecoder(req.Body).Decode(&user)

	fmt.Printf("Signup %v, %v\n\n", user.Username, user.Password)

	_, err := db.Exec("INSERT INTO users (Username, Password) VALUES (?, ?)", user.Username, user.Password)
	if err != nil {
		fmt.Printf("Error querying database: %v\n\n", err)
		http.Error(w, "Couldn't add to database", http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}
