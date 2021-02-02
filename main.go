package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"strings"

	"database/sql"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"

	"time"
)

var db *sql.DB
var createdJWT string
var secret []byte = []byte("notReallyASecret")

type PLang struct {
	ID   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type User struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func GetPLanguageEndpoint(w http.ResponseWriter, req *http.Request) { //deprecated
	params := mux.Vars(req)

	fmt.Println("GET", params["id"], time.Now(), "\n")

	rows, _ := db.Query("SELECT PLangID, Name FROM programming_languages WHERE PLangID = ?", params["id"])

	for rows.Next() {
		var pLang PLang
		rows.Scan(&pLang.ID, &pLang.Name)
		json.NewEncoder(w).Encode(&pLang)
		return
	}

	json.NewEncoder(w).Encode(&PLang{})
}

func GetPLanguagesEndpoint(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET", time.Now())
	fmt.Println("Headers:", req.Header, "\n")

	pLangs := []PLang{}

	token, _ := jwt.Parse(strings.Split(req.Header.Get("Authorization"), " ")[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	claims := token.Claims.(jwt.MapClaims) //what is this

	rows, _ := db.Query("SELECT PLangID, programming_languages.Name FROM programming_languages, users, users_programming_languages WHERE users.Username = ? AND users.UserID = users_programming_languages.User AND programming_languages.PLangID = users_programming_languages.PLang", claims["username"])

	var pLangID int
	var pLangName string

	for rows.Next() {
		rows.Scan(&pLangID, &pLangName)
		pLangs = append(pLangs, PLang{ID: pLangID, Name: pLangName})
	}

	fmt.Println("GET pLangs:", pLangs)
	fmt.Println("pLangs length:", len(pLangs))
	json.NewEncoder(w).Encode(&pLangs)
}

func AddPLanguageEndpoint(w http.ResponseWriter, req *http.Request) {
	token, _ := jwt.Parse(strings.Split(req.Header.Get("Authorization"), " ")[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	claims := token.Claims.(jwt.MapClaims) //what is this

	var pLang PLang
	json.NewDecoder(req.Body).Decode(&pLang)

	fmt.Println("POST", time.Now(), "\n", pLang.ID, "\n", pLang.Name)

	insertRes, _ := db.Exec("INSERT INTO users_programming_languages (User, PLang) SELECT UserID, PLangID FROM users, programming_languages WHERE Username = ? AND Name = ?", claims["username"], pLang.Name)

	rowsAffected, _ := insertRes.RowsAffected()
	insertedID, _ := insertRes.LastInsertId()

	fmt.Printf("Rows affected by INSERT: %v\nLast inserted ID: %v\n", rowsAffected, insertedID)

	if rowsAffected == 0 {
		insertRes, _ = db.Exec("INSERT INTO programming_languages (Name) VALUES (?)", pLang.Name)
		insertedLangID, _ := insertRes.LastInsertId()
		_, er := db.Exec("INSERT INTO users_programming_languages (User, PLang) SELECT UserID, PLangID FROM users, programming_languages WHERE Username = ? AND PLangID = ?", claims["username"], insertedLangID)
		fmt.Printf("Inserting new language for a user error: %v\n", er)
	}

	GetPLanguagesEndpoint(w, req)
}

func EditPLanguageEndpoint(w http.ResponseWriter, req *http.Request) {
	token, _ := jwt.Parse(strings.Split(req.Header.Get("Authorization"), " ")[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	claims := token.Claims.(jwt.MapClaims) //what is this

	newAndOldPLangs := struct {
		NameToEdit string
		NewName string
	}{}

	json.NewDecoder(req.Body).Decode(&newAndOldPLangs)

	fmt.Printf("newAndOldPLangs: %v\n", newAndOldPLangs)
	fmt.Printf("Edit %v to %v\n\n", newAndOldPLangs.NameToEdit, newAndOldPLangs.NewName)

	//fmt.Println("PUT", time.Now(), "\n", pLang.ID, "\n", pLang.Name, "\n")

	/*stmt := "UPDATE programming_languages SET " //More flexible
	presentParamsCounter := 0
	if pLang.ID != 0 {
		stmt += "PLangID = ?"
		presentParamsCounter++
	}
	if pLang.Name != "" {
		if presentParamsCounter >= 1 {
			stmt += ", Name = ?"
		} else {
			stmt += "Name = ?"
		}
		presentParamsCounter++
	}
	stmt += "WHERE PLangID = ?"*/

	_, err := db.Exec("UPDATE users_programming_languages SET PLang = (SELECT PLangID FROM programming_languages WHERE Name = ?) WHERE User = (SELECT UserID FROM users WHERE Username = ?) AND PLang = (SELECT PLangID FROM programming_languages WHERE Name = ?)", newAndOldPLangs.NewName, claims["username"], newAndOldPLangs.NameToEdit)

	if err == nil {
		w.WriteHeader(http.StatusOK)
	}
}

func DeletePLanguageEndpoint(w http.ResponseWriter, req *http.Request) {
	token, _ := jwt.Parse(strings.Split(req.Header.Get("Authorization"), " ")[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})
	claims, _ := token.Claims.(jwt.MapClaims)

	params := mux.Vars(req)

	fmt.Println("DELETE", params["id"], claims["username"], time.Now(), "\n")

	_, err := db.Exec("DELETE FROM users_programming_languages WHERE User = (SELECT UserID FROM users WHERE Username = ?) AND PLang = ?", claims["username"], params["id"])
	fmt.Println("The error for DELETE query", err)

	GetPLanguagesEndpoint(w, req)
}

func LoginEndpoint(w http.ResponseWriter, req *http.Request) {
	var user User

	fmt.Println(user.Username)
	fmt.Println(user.Password)

	json.NewDecoder(req.Body).Decode(&user)

	fmt.Println("Decoded body:")
	fmt.Println(user.Username)
	fmt.Println(user.Password)

	rows, errDB := db.Query("SELECT Username, Password FROM programming_languages.users WHERE Username = ? AND Password = ?", user.Username, user.Password)
	if errDB != nil {
		fmt.Println("Error querying database")
	}

	user.Username = ""
	user.Password = ""

	for rows.Next() {
		rows.Scan(&user.Username, &user.Password)
	}

	fmt.Println("Query result:")
	fmt.Println(user.Username)
	fmt.Println(user.Password)

	if user.Username != "" && user.Password != "" {
		fmt.Println("Found the user in the database")
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username":            user.Username, // TODO: should send user's id instead
			"userPermissionLevel": "0",
		})
		createdJWT, _ = token.SignedString(secret)
		fmt.Printf("JWT for %v: %v\n\n", user.Username, createdJWT)
		w.Header().Set("Authorization", "Bearer "+createdJWT)
	} else {
		fmt.Println("No such user found")
	}
}

func SignupEndpoint(w http.ResponseWriter, req *http.Request) { //probably should be more validation and acknowledgment
	var user User

	json.NewDecoder(req.Body).Decode(&user)

	db.Exec("INSERT INTO users (Username, Password) VALUES (?, ?)", user.Username, user.Password)

	w.WriteHeader(http.StatusOK)
}

func JWTmiddleware(next http.Handler) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		fmt.Println("JWT middleware activated")

		if createdJWT == strings.Split(req.Header.Get("Authorization"), " ")[1] { // TODO: Make index-out-of-range safe
			fmt.Println("Authorized with JWT middleware\n")
			next.ServeHTTP(w, req)
		} else {
			fmt.Println("JWTs are not the same\n")
			w.WriteHeader(http.StatusUnauthorized)
		}
	}
}

func main() {
	fmt.Println("A server\n")
	fmt.Println("Opening database")
	var errDB error
	db, errDB = sql.Open("mysql", "root:password@tcp(localhost:3306)/programming_languages")
	if errDB == nil { //Useless, no error if MySQL is not working
		fmt.Println("Database opened successfuly\n")
	} else {
		fmt.Println("Couldn't open database\n")
	}
	defer db.Close()

	router := mux.NewRouter()
	router.HandleFunc("/PLanguages/{id}", JWTmiddleware(http.HandlerFunc(GetPLanguageEndpoint))).Methods("GET")
	router.HandleFunc("/PLanguages", JWTmiddleware(http.HandlerFunc(GetPLanguagesEndpoint))).Methods("GET")
	router.HandleFunc("/PLanguages", JWTmiddleware(http.HandlerFunc(AddPLanguageEndpoint))).Methods("POST")
	router.HandleFunc("/PLanguages/{id}", JWTmiddleware(http.HandlerFunc(DeletePLanguageEndpoint))).Methods("DELETE")
	router.HandleFunc("/PLanguages", JWTmiddleware(http.HandlerFunc(EditPLanguageEndpoint))).Methods("PUT")
	router.HandleFunc("/login", LoginEndpoint).Methods("POST")
	router.HandleFunc("/signup", SignupEndpoint).Methods("POST")

	log.Fatal(http.ListenAndServe(":8085", router))
}
