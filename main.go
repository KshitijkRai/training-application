package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
)

// User type
type User struct {
	Firstname string
	Lastname  string
	Email     string
	Password  string
}

var tpl *template.Template      // *template.Template is like a container that holds all the templates
var db *sql.DB                  // Database pointer
var dbUsers = map[string]User{} // userId, user

/*
A session variable is a special type of variable whose value is maintained across subsequent web pages.
With session variables, user-specific data can be preserved from page to page delivering customized
content as the user interacts with the web application. Session variables normally exist until one of
the follow criteria is met:
1. the user closes the browser window;
2. the maximum time allotment set on the server for session lifetime is exceeded;
*/
var dbSessions = map[string]string{} // sessionId, userId

// init function always runs once
func init() {
	// Must is a helper that wraps a call to a function returning (*Template, error) and panics if the error is non-nil
	// func Must(t *Template, err error) *Template
	tpl = template.Must(template.ParseGlob("templates/*"))

	// Database connection
	var err error
	connStr := "postgres://postgres:password@localhost/postgres?sslmode=disable"
	// func Open(driverName string, dataSourceName string) (*DB, error)
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	// Ping verifies a connection to the database is still alive, establishing a connection if necessary
	// func (db *DB) Ping() error
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully connected to database")
	fmt.Println(db.Stats())
}

func main() {
	// Close closes the database and prevents new queries from starting
	defer db.Close()

	// func HandleFunc(pattern string, handler func(ResponseWriter, *Request))
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/welcome", welcome)

	// Handle registers the handler for the given pattern in the DefaultServeMux
	// func Handle(pattern string, handler Handler)
	http.Handle("favicon.ico", http.NotFoundHandler())

	// func ListenAndServe(addr string, handler Handler) error
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func index(writer http.ResponseWriter, request *http.Request) {
	err := tpl.ExecuteTemplate(writer, "index.gohtml", dbSessions)
	if err != nil {
		panic(err)
	}
}

func login(writer http.ResponseWriter, request *http.Request) {
	// Go to welcome page if user is already logged in
	if alreadyLoggedIn(request) {
		http.Redirect(writer, request, "/welcome", http.StatusSeeOther)
		return
	}
	// Check if request method is POST
	if request.Method == http.MethodPost {
		enteredEmail := request.FormValue("email")
		enteredPassword := request.FormValue("password")

		// Check if userId already exists
		// QueryRow executes a query that is expected to return at most one row
		// func (db *DB) QueryRow(query string, args ...interface{}) *Row
		rows := db.QueryRow("SELECT * FROM user_login WHERE email = $1;", enteredEmail)

		var user User
		// Scan copies the columns from the matched row into the values pointed at by dest
		// func (r *Row) Scan(dest ...interface{}) error
		err := rows.Scan(&user.Firstname, &user.Lastname, &user.Email, &user.Password)
		fmt.Println(user)
		// ErrNoRows is returned by Scan when QueryRow doesn't return a row
		// var ErrNoRows error = errors.New("sql: no rows in result set")
		if err == sql.ErrNoRows {
			panic(err)
		}

		// Does the entered password match the stored password?
		// CompareHashAndPassword compares a bcrypt hashed password with its possible plaintext equivalent.
		// Returns nil on success, or an error on failure.
		// func CompareHashAndPassword(hashedPassword []byte, password []byte) error
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(enteredPassword))
		if err != nil {
			panic("Wrong password")
		}

		// Create session id
		sessionId := uuid.NewV4()

		// Create cookie
		cookie := &http.Cookie{
			Name:     "session",
			Value:    sessionId.String(),
			HttpOnly: true,
		}

		// Set cookie
		http.SetCookie(writer, cookie)

		// Save session
		// dbSessions[key: d90af075-3969-44c9-8d4c-08d9858bdbd8] = value: test@test.com
		// {key: d90af075-3969-44c9-8d4c-08d9858bdbd8, value: test@test.com}
		dbSessions[cookie.Value] = enteredEmail

		// Redirect to homepage
		http.Redirect(writer, request, "/welcome", http.StatusSeeOther)
		return
	}
	// If request method is not POST, display signup page.
	err := tpl.ExecuteTemplate(writer, "login.gohtml", nil)
	if err != nil {
		panic(err)
	}
}

func logout(writer http.ResponseWriter, request *http.Request) {
	// Go to homepage if the is already logged in
	if !alreadyLoggedIn(request) {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}

	// Get cookie
	cookie, _ := request.Cookie("session")

	// Delete session
	delete(dbSessions, cookie.Value)

	// Remove cookie
	cookie = &http.Cookie{
		Name:     "session",
		Value:    "",
		HttpOnly: true,
	}

	// Set cookie
	http.SetCookie(writer, cookie)

	// Redirect to login page
	http.Redirect(writer, request, "/login", http.StatusSeeOther)
	return
}

func signup(writer http.ResponseWriter, request *http.Request) {
	// Go to welcome page if user is already logged in
	if alreadyLoggedIn(request) {
		http.Redirect(writer, request, "/welcome", http.StatusSeeOther)
		return
	}
	// Check if request method is POST
	if request.Method == http.MethodPost {
		firstname := request.FormValue("firstname")
		lastname := request.FormValue("lastname")
		email := request.FormValue("email")
		password := request.FormValue("password")

		// Check if userId already exists
		rows := db.QueryRow("SELECT email FROM user_login WHERE email = $1;", email)

		var userId string
		// Scan copies the columns from the matched row into the values pointed at by dest
		// func (r *Row) Scan(dest ...interface{}) error
		err := rows.Scan(&userId)
		// ErrNoRows is returned by Scan when QueryRow doesn't return a row
		// var ErrNoRows error = errors.New("sql: no rows in result set")
		if err != sql.ErrNoRows {
			panic("User id not available")
		}

		// Encrypt password
		// Do not save normal password
		var encryptedPassword []byte
		// func GenerateFromPassword(password []byte, cost int) ([]byte, error)
		encryptedPassword, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			panic(err)
		}

		// Create new user
		newUser := User{firstname, lastname, email, string(encryptedPassword)}

		// func (s *Stmt) Exec(args ...interface{}) (Result, error)
		_, err = db.Exec("INSERT INTO user_login (firstname, lastname, email, password) VALUES ($1, $2, $3, $4);",
			newUser.Firstname, newUser.Lastname, newUser.Email, newUser.Password)
		if err != nil {
			panic(err)
		}

		// Creating UUID Version 4
		sessionId := uuid.NewV4()

		// Create cookie
		cookie := &http.Cookie{
			Name:     "session",
			Value:    sessionId.String(),
			HttpOnly: true,
		}

		// Set cookie
		http.SetCookie(writer, cookie)

		// dbSessions[key: d90af075-3969-44c9-8d4c-08d9858bdbd8] = value: test@test.com
		// {key: d90af075-3969-44c9-8d4c-08d9858bdbd8, value: test@test.com}
		dbSessions[cookie.Value] = email

		// After successful signup, go to welcome page.
		http.Redirect(writer, request, "/welcome", http.StatusSeeOther)
		return
	}
	// If request method is not POST, display signup page.
	err := tpl.ExecuteTemplate(writer, "signup.gohtml", "Click to go back to homepage")
	if err != nil {
		panic(err)
	}
}

func welcome(writer http.ResponseWriter, request *http.Request) {
	// Query executes a query that returns rows, typically a SELECT. The args are for any placeholder parameters in the query.
	// func (db *DB) Query(query string, args ...interface{}) (*Rows, error)
	rows, err := db.Query("SELECT * FROM user_login;")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var user User
	// func (rs *Rows) Next() bool
	users := make([]User, 0)
	for rows.Next() {
		// Scan copies the columns in the current row into the values pointed at by dest.
		// The number of values in dest must be the same as the number of columns in Rows.
		// func (rs *Rows) Scan(dest ...interface{}) error
		err := rows.Scan(&user.Firstname, &user.Lastname, &user.Email, &user.Password)
		if err != nil {
			panic(err)
		}
		users = append(users, user)
	}

	err = tpl.ExecuteTemplate(writer, "welcome.gohtml", users)
	if err != nil {
		panic(err)
	}
}

func alreadyLoggedIn(request *http.Request) bool {
	cookie, err := request.Cookie("session")
	if err != nil {
		return false
	}

	rows := db.QueryRow("SELECT * FROM user_login WHERE email = $1;", dbSessions[cookie.Value])

	var user User
	err = rows.Scan(&user)
	if err != sql.ErrNoRows {
		return true
	}
	return false
}

func getUser(writer http.ResponseWriter, request *http.Request) User {
	cookie, err := request.Cookie("session")
	if err != nil {
		sessionId := uuid.NewV4()
		cookie := &http.Cookie{
			Name:     "session",
			Value:    sessionId.String(),
			HttpOnly: true,
		}
		http.SetCookie(writer, cookie)
	}

	// QueryRow executes a query that is expected to return at most one row
	// func (db *DB) QueryRow(query string, args ...interface{}) *Row
	rows := db.QueryRow("SELECT * FROM user_login WHERE email = $1;", cookie.Value)

	var user User
	// Scan copies the columns from the matched row into the values pointed at by dest
	// func (r *Row) Scan(dest ...interface{}) error
	err = rows.Scan(&user.Firstname, &user.Lastname, &user.Email, &user.Password)
	fmt.Println(user)
	// ErrNoRows is returned by Scan when QueryRow doesn't return a row
	// var ErrNoRows error = errors.New("sql: no rows in result set")
	if err == sql.ErrNoRows {
		panic(err)
	}
	return user
}
