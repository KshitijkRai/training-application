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

// User type to hold user details
type User struct {
	Firstname string
	Lastname  string
	Email     string
	Password  string
}

// A container to hold templates
var tpl *template.Template

// Pointer
var db *sql.DB

// Create a variable that holds all the users
// This will become redundant once we use database to save users
var dbUsers = map[string]User{} // userId, user

// Create a variable that holds all the sessions
// Save sessions in the app rather than database
var dbSessions = map[string]string{} // sessionId, userId

// init function always runs once
func init() {
	// Parse templates on start. This prepares the templates to be used later.
	tpl = template.Must(template.ParseGlob("templates/*"))

	// Connect to database
	var err error
	connStr := "postgres://postgres:password@localhost/postgres?sslmode=disable"
	// Open opens a database specified by its database driver name and a driver-specific data source name, usually consisting of at least a database name and connection information.
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Invalid database config", err)
	}

	// Ping verifies a connection to the database is still alive, establishing a connection if necessary.
	if err = db.Ping(); err != nil {
		log.Fatal("Database unreachable", err)
	}
	fmt.Println("You are connected to database")
}

func main() {
	// If the database connections is established in init do not close in init. This will close the connection immediately.
	// Always close the connection in main
	defer db.Close()

	// Create handlers
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/welcome", welcome)

	// Missing favicon handler. If the favicon is missing, this will handle the request.
	http.Handle("favicon.ico", http.NotFoundHandler())

	// Run local server.
	// If you use Heroku, you dont need this. You have to user Heroku environment variable to run the server.
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func index(writer http.ResponseWriter, request *http.Request) {
	// Go to welcome page if the user is already logged in
	if alreadyLoggedIn(request) {
		// Go to welcome page if the user is already logged in
		http.Redirect(writer, request, "/welcome", http.StatusSeeOther)
		return
	}
	// Else, go to homepage
	err := tpl.ExecuteTemplate(writer, "index.gohtml", dbUsers)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func login(writer http.ResponseWriter, request *http.Request) {
	// Go to welcome page if the user is already logged in
	if alreadyLoggedIn(request) {
		// Go to welcome page if the user is already logged in
		http.Redirect(writer, request, "/welcome", http.StatusSeeOther)
		return
	}
	// Else go to login page
	// Process login if the method is GET
	if request.Method == http.MethodPost {
		// Retrieve values from form
		enteredEmail := request.FormValue("email")
		enteredPassword := request.FormValue("password")

		// Check if userId exists
		checkUser, ok := dbUsers[enteredEmail]
		if !ok {
			http.Error(writer, "User not found", http.StatusForbidden)
			return
		}

		// Does the entered password match the stored password?
		err := bcrypt.CompareHashAndPassword([]byte(checkUser.Password), []byte(enteredPassword))
		if err != nil {
			http.Error(writer, "Password do not match", http.StatusForbidden)
			return
		}

		// If both userId and password match, create new session.
		sessionId, _ := uuid.NewV4()

		// Create new cookie
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
	}
	// Else skip login process and display login form
	err := tpl.ExecuteTemplate(writer, "login.gohtml", nil)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func logout(writer http.ResponseWriter, request *http.Request) {
	// Go to homepage if the user is already logged in
	if !alreadyLoggedIn(request) {
		// Go to login page if the user is not logged in
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	// Else user is not logged in

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
}

func signup(writer http.ResponseWriter, request *http.Request) {
	// Go to welcome page if the user is already logged in
	if alreadyLoggedIn(request) {
		// Go to welcome page if the user is already logged in
		http.Redirect(writer, request, "/welcome", http.StatusSeeOther)
		return
	}
	/*
		Things to do -

		1. Check if the method is post or not
		2. Get form values
		3. Check if userId already exists
			3.1. Replaces dbUsers with database
		4. Encrypt password
		5. Create new user
		6. Create new session
		7. Create new cookie
		8. Set cookie
		9. Save session
		10. Save new user
	*/
	// Else process sign up
	// Process sign up if action is POST
	if request.Method == http.MethodPost {
		firstname := request.FormValue("firstname")
		lastname := request.FormValue("lastname")
		email := request.FormValue("email")
		password := request.FormValue("password")

		// Check if userId already exists
		rows, err := db.Query("SELECT email FROM user_login WHERE email = $1", email)
		if err != nil {
			panic(err)
		}
		// You have to close the rows after query
		defer rows.Close()

		// Create a variable that will hold userId retrieved from query above
		var userId string
		// Loop through rows
		// Next prepares the next result row for reading with the Scan method. It returns true on success, or false if
		// there is no next result row or an error happened while preparing it.
		for rows.Next() {
			// Save rows into userId
			// rows.Scan cannot run without rows.Next()
			// Scan copies the columns in the current row into the values pointed at by dest.
			// The number of values in dest must be the same as the number of columns in Rows
			err = rows.Scan(&userId)
			if err != nil {
				panic(err)
			}
		}

		// Encrypt password with bcrypt hash
		var encryptedPassword []byte
		// GenerateFromPassword returns the bcrypt hash of the password at the given cost.
		// If the cost given is less than MinCost, the cost will be set to DefaultCost, instead.
		// Use CompareHashAndPassword, as defined in this package,
		// to compare the returned hashed password with its cleartext version
		// func GenerateFromPassword(password []byte, cost int) ([]byte, error)
		encryptedPassword, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		// Create new user
		newUser := User{firstname, lastname, email, string(encryptedPassword)}

		// Create new session id
		sessionId, _ := uuid.NewV4()

		// Create new cookie
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
		dbSessions[cookie.Value] = email

		// Save user
		// dbUsers[key: test@test.com] = value: user{firstname, lastname, email, string(encryptedPassword)}
		// {key: test@test.com, value: user{firstname, lastname, email, string(encryptedPassword)}}
		dbUsers[email] = newUser

		// Debug
		fmt.Println("User:", newUser)
		fmt.Println("Cookie:", cookie)
		fmt.Println("DB Sessions:", dbSessions)
		fmt.Println("DB Users:", dbUsers)

		// Redirect to homepage
		http.Redirect(writer, request, "/welcome", http.StatusSeeOther)
		return
	}
	// Else skip sign up process and display sign up form
	err := tpl.ExecuteTemplate(writer, "signup.gohtml", "Click to go back to homepage")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func welcome(writer http.ResponseWriter, request *http.Request) {
	// Go to welcome page if the user is already logged in
	if !alreadyLoggedIn(request) {
		// Go to welcome page if the user is already logged in
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	err := tpl.ExecuteTemplate(writer, "welcome.gohtml", dbSessions)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
}

func alreadyLoggedIn(request *http.Request) bool {
	// Returns true if user is already logged in, else returns false.

	/*
		Things to do -

		1. Get cookie from request
		2. Return false if cookie doesn't exist
		3. Return userId from dbSessions
		4. Check if userId matches with any key in dbUsers
		5. Return true
	*/

	// Get cookie
	cookie, err := request.Cookie("session")
	if err != nil {
		// Return false if cookie is not found
		return false
	}

	// Return userId from dbSessions where key is equals to cookie value
	userId := dbSessions[cookie.Value]
	// Check if userId matches with any key in dbUsers
	_, ok := dbUsers[userId]
	return ok
}

func getUser(writer http.ResponseWriter, request *http.Request) User {
	/*
		Things to do -

		1. Get cookie from request
		2. Create new session
		3. Create new cookie
		4. Set cookie
		4. Check if userId matches with any key in dbSessions
		5. Return user if exist
	*/
	cookie, err := request.Cookie("session")
	if err != nil {
		// Create new session id
		sessionId, _ := uuid.NewV4()

		// Create new cookie
		cookie := &http.Cookie{
			Name:     "session",
			Value:    sessionId.String(),
			HttpOnly: true,
		}

		// Set cookie
		http.SetCookie(writer, cookie)
	}

	// If the user already exists, get user.
	var user User
	if userId, ok := dbSessions[cookie.Value]; ok {
		user = dbUsers[userId]
	}
	return user
}
