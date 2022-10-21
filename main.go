package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"unicode"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

var inLog *log.Logger
var errLog *log.Logger
var db *sql.DB
var rc RequestCounter

func init() {
	inLog = log.New(os.Stdout, "[INFO]::", log.LstdFlags)
	errLog = log.New(os.Stderr, "[ERROR]::", log.LstdFlags)
	rc = RequestCounter{counter: 0}
}

func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)

	myRouter.HandleFunc("/polls/", getPolls).Methods("GET")
	myRouter.HandleFunc("/polls/{id}", getOnePoll).Methods("GET")
	myRouter.HandleFunc("/register/", registerPoll).Methods("POST")

	errLog.Fatal(http.ListenAndServe(":8000", myRouter))
}

type Auth struct {
	Login   string
	PwdHash []byte
}

type PollReadOnly struct {
	Id        string `json:"id"`
	Fname     string `json:"first_name"`
	Lname     string `json:"last_name"`
	Age       int    `json:"age"`
	Interests string `json:"interests"`
	City      string `json:"city"`
}

type PollWrite struct {
	Fname     string `json:"first_name"`
	Lname     string `json:"last_name"`
	Age       int    `json:"age"`
	Interests string `json:"interests" default:""`
	City      string `json:"city"`
	Login     string `json:"login"`
	Pwd       string `json:"password"`
}

type JSONmsg struct {
	Code    int    `json:"status_code"`
	Message string `json:"message"`
}

type RequestCounter struct {
	mu      sync.Mutex
	counter int
}

func (rc *RequestCounter) inc() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.counter++
}

func CheckAuth(r *http.Request) (bool, error) {
	l, p, ok := r.BasicAuth()
	if !ok {
		return false, fmt.Errorf("couldn't parse basic auth")
	}

	var cred Auth
	err := db.QueryRow("SELECT login, password FROM polls WHERE login=?",
		l).Scan(&cred.Login, &cred.PwdHash)
	if err != nil {
		if err == sql.ErrNoRows {
			errLog.Printf("Couldn't get user %s", cred.Login)
			return false, fmt.Errorf("wrong username or password")
		}
		errLog.Printf("%s", err.Error())
		return false, fmt.Errorf("couldn't authenticate")
	}

	if l != cred.Login {
		errLog.Printf("Couldn't get user %s", l)
		return false, fmt.Errorf("wrong username or password")
	}

	pwdHash, err := hashPwd(&p)
	if err != nil {
		errLog.Printf("Couldn't get password hash %s", err.Error())
		return false, fmt.Errorf("couldn't authenticate")
	}

	for i, v := range pwdHash {
		if v != cred.PwdHash[i] {
			errLog.Printf("wrong password")
			return false, fmt.Errorf("wrong username or password")
		}
	}
	return true, nil
}

func getPolls(w http.ResponseWriter, r *http.Request) {
	rc.inc()
	inLog.Printf("REQUEST #%d METHOD: %s URI: %s", rc.counter, r.Method, r.RequestURI)

	_, err := CheckAuth(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		errLog.Printf(err.Error())
		jsonErr := JSONmsg{Code: 401, Message: err.Error()}
		json.NewEncoder(w).Encode(jsonErr)
		return
	}

	rows, err := db.Query("SELECT id, fname, lname, age, interests, city FROM polls")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errLog.Printf("Couldn't get users: %s", err.Error())
		jsonErr := JSONmsg{Code: 500, Message: err.Error()}
		json.NewEncoder(w).Encode(jsonErr)
		return
	}
	defer rows.Close()
	var polls []PollReadOnly

	for rows.Next() {
		var poll PollReadOnly

		err := rows.Scan(&poll.Id, &poll.Fname, &poll.Lname, &poll.Age, &poll.Interests, &poll.City)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			errLog.Printf("Couldn't scan user: %s", err.Error())
			jsonErr := JSONmsg{Code: 500, Message: err.Error()}
			json.NewEncoder(w).Encode(jsonErr)
			return
		}
		polls = append(polls, poll)
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(polls)
}

func getOnePoll(w http.ResponseWriter, r *http.Request) {
	rc.inc()
	inLog.Printf("REQUEST #%d METHOD: %s URI: %s", rc.counter, r.Method, r.RequestURI)
	_, err := CheckAuth(r)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		errLog.Printf(err.Error())
		jsonErr := JSONmsg{Code: 401, Message: err.Error()}
		json.NewEncoder(w).Encode(jsonErr)
		return
	}

	if r.Method == "GET" {
		vars := mux.Vars(r)
		id := vars["id"]

		var poll PollReadOnly
		err := db.QueryRow("SELECT id, fname, lname, age, interests, city FROM polls WHERE id=?",
			id).Scan(&poll.Id, &poll.Fname, &poll.Lname, &poll.Age, &poll.Interests, &poll.City)
		if err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusNoContent)
				errLog.Printf("No user with id=%s", id)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			errLog.Printf("Couldn't get user: %s", err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(poll)
	}

}

func registerPoll(w http.ResponseWriter, r *http.Request) {
	rc.inc()
	inLog.Printf("REQUEST #%d METHOD: %s URI: %s", rc.counter, r.Method, r.RequestURI)
	reqBody, _ := ioutil.ReadAll(r.Body)
	var poll PollWrite
	json.Unmarshal(reqBody, &poll)

	isValid := isValidLogin(&poll.Login)

	if !isValid {
		w.WriteHeader(http.StatusBadRequest)
		errLog.Printf("Invalid login input: %s", poll.Login)
		jsonErr := JSONmsg{Code: 400, Message: fmt.Sprintf("Invalid login input %s", poll.Login)}
		json.NewEncoder(w).Encode(jsonErr)
		return
	}

	pwdHash, err := hashPwd(&poll.Pwd)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errLog.Printf("Couldn't hash password: %s", err.Error())
		jsonErr := JSONmsg{Code: 500, Message: err.Error()}
		json.NewEncoder(w).Encode(jsonErr)
		return
	}

	insert, err := db.Query(
		`INSERT INTO polls (fname, lname, age, city, interests, login, password)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		`, poll.Fname, poll.Lname, poll.Age, poll.City, poll.Interests, poll.Login, pwdHash)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		errLog.Printf("Couldn't insert user: %s", err.Error())
		jsonErr := JSONmsg{Code: 500, Message: err.Error()}
		json.NewEncoder(w).Encode(jsonErr)
		return
	}
	defer insert.Close()
	w.WriteHeader(http.StatusCreated)
	jsonMsg := JSONmsg{Code: 201, Message: fmt.Sprintf("Poll for %s created", poll.Login)}
	json.NewEncoder(w).Encode(jsonMsg)
	inLog.Printf("REQUEST #%d SUCCESSFUL", rc.counter)
}

func hashPwd(s *string) ([]byte, error) {
	h := sha256.New()
	_, err := h.Write([]byte(*s))
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func isValidLogin(s *string) bool {
	if len(*s) < 4 {
		return false
	}
	for _, c := range *s {
		if c > unicode.MaxASCII {
			return false
		}
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

func init_db(db *sql.DB) {
	table, err := db.Query(`
	CREATE TABLE IF NOT EXISTS polls (
		id int NOT NULL AUTO_INCREMENT,
		fname varchar(100) NOT NULL,
		lname varchar(100) NOT NULL,
		age int NOT NULL,
		city varchar(100) NOT NULL,
		interests varchar(256) DEFAULT NULL,
		login varchar(20) NOT NULL,
		password binary(32) NOT NULL,
		CONSTRAINT pk_polls PRIMARY KEY (id),
		CONSTRAINT unique_login UNIQUE (login) 
	)
	`)
	if err != nil {
		errLog.Fatalf("Failed to init database: %s", err.Error())
	}
	defer table.Close()
}

func main() {
	inLog.Println("Launching OTUS Simple Social Media API Server")

	inLog.Println("Reading environment variables")
	err := godotenv.Load()
	if err != nil {
		errLog.Fatalf("Error loading .env file: %s", err.Error())
	}

	dbName := os.Getenv("MYSQL_DATABASE")
	dbHost := os.Getenv("MYSQL_HOST")
	dbUser := os.Getenv("MYSQL_USER")
	dbPwd := os.Getenv("MYSQL_PASSWORD")

	inLog.Println("Connecting to database")
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", dbUser, dbPwd, dbHost, dbName))
	if err != nil {
		errLog.Fatalf("Failed to connect to db: %s", err.Error())
	}
	defer db.Close()

	inLog.Println("Initilizing database")
	init_db(db)

	inLog.Println("Finished preparation. Start to handling requests")
	handleRequests()
}
