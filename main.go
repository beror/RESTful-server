package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"

	"database/sql"
	_ "github.com/go-sql-driver/mysql"

	"time"
)

var db *sql.DB

func main() {
	fmt.Println("Programming languages and users server\n")
	fmt.Println("Connecting to database")
	var errOpen error
	db, errOpen = sql.Open("mysql", "root:password@tcp(localhost:3306)/programming_languages")
	errPing := db.Ping()
	if errPing != nil || errOpen != nil {
		fmt.Printf("Error establishing connection to database:\nOpen() error: %v\nPing() error: %v", errOpen, errPing)
		db.Close()
		time.Sleep(3 * time.Second)
		return
	} else {
		fmt.Println("Successfully connected to database\n")
	}
	defer db.Close()

	router := mux.NewRouter()
	router.Handle("/PLanguages", JWTmiddleware(GetPLanguagesEndpoint)).Methods("GET")
	router.Handle("/PLanguages", JWTmiddleware(AddPLanguageEndpoint)).Methods("POST")
	router.Handle("/PLanguages/{id}", JWTmiddleware(DeletePLanguageEndpoint)).Methods("DELETE")
	router.Handle("/PLanguages", JWTmiddleware(EditPLanguageEndpoint)).Methods("PUT")
	router.HandleFunc("/login", LoginEndpoint).Methods("POST")
	router.HandleFunc("/signup", SignupEndpoint).Methods("POST")

	log.Fatal(http.ListenAndServe(":8085", router))
}
