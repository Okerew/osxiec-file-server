package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

const (
	uploadDir     = "./uploads"
	maxUploadSize = 20 << 20 // 20 MB
	dbFile        = "./cdn.db"
)

var db *sql.DB

func main() {
	// Open the database, if not found, create it
	var err error
	db, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			username TEXT NOT NULL
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS stars (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        UNIQUE(file_id, username),
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(username) REFERENCES users(username)
    )
`)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/search", searchHandler)
	mux.HandleFunc("/user-files", userFilesHandler)
	mux.HandleFunc("/remove", removeFileHandler)
	mux.HandleFunc("/star", starHandler)
	mux.HandleFunc("/starred-files", starredFilesHandler)
	mux.HandleFunc("/reset", resetPasswordHandler)
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(mux)

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// Decode the request body into the user struct

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, string(hashedPassword))
	if err != nil {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", user.Username).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	if !strings.HasSuffix(header.Filename, ".bin") {
		http.Error(w, "Only .bin files are allowed", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Verify the user's credentials
	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Check if a file with the same name already exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE name = ?", header.Filename).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "A file with this name already exists", http.StatusConflict)
		return
	}

	description := r.FormValue("description")

	err = os.MkdirAll(uploadDir, os.ModePerm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filename := filepath.Join(uploadDir, header.Filename)
	out, err := os.Create(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO files (name, description, username) VALUES (?, ?, ?)", header.Filename, description, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fileURL := fmt.Sprintf("http://%s/files/%s", r.Host, header.Filename)
	fmt.Fprint(w, fileURL)
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	term := r.URL.Query().Get("term")
	username := r.URL.Query().Get("username") // Add this line to get the current user

	if term == "" {
		http.Error(w, "Search term is required", http.StatusBadRequest)
		return
	}

	query := `
        SELECT f.name, f.description, f.username, 
               (SELECT COUNT(*) FROM stars WHERE file_id = f.id) as star_count,
               (SELECT COUNT(*) FROM stars WHERE file_id = f.id AND username = ?) as is_starred
        FROM files f
        WHERE f.name LIKE ? OR f.description LIKE ?
    `
	rows, err := db.Query(query, username, "%"+term+"%", "%"+term+"%")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var name, description, fileUsername string
		var starCount, isStarred int
		err := rows.Scan(&name, &description, &fileUsername, &starCount, &isStarred)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		results = append(results, map[string]interface{}{
			"name":        name,
			"url":         fmt.Sprintf("http://%s/files/%s", r.Host, name),
			"description": description,
			"username":    fileUsername,
			"starCount":   starCount,
			"isStarred":   isStarred > 0,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func userFilesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.URL.Query().Get("username")
	currentUser := r.URL.Query().Get("currentUser")

	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	query := `
        SELECT f.name, f.description, 
               (SELECT COUNT(*) FROM stars WHERE file_id = f.id) as star_count,
               (SELECT COUNT(*) FROM stars WHERE file_id = f.id AND username = ?) as is_starred
        FROM files f
        WHERE f.username = ?
    `
	rows, err := db.Query(query, currentUser, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var name, description string
		var starCount, isStarred int
		err := rows.Scan(&name, &description, &starCount, &isStarred)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		files = append(files, map[string]interface{}{
			"name":        name,
			"url":         fmt.Sprintf("http://%s/files/%s", r.Host, name),
			"description": description,
			"starCount":   starCount,
			"isStarred":   isStarred > 0,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func removeFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Filename string `json:"filename"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the user's credentials
	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", request.Username).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(request.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Check if the file belongs to the user
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE username = ? AND name = ?", request.Username, request.Filename).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count == 0 {
		http.Error(w, "File not found or you don't have permission to remove it", http.StatusForbidden)
		return
	}

	// Remove the file from the database
	_, err = db.Exec("DELETE FROM files WHERE username = ? AND name = ?", request.Username, request.Filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Remove the file from the filesystem
	err = os.Remove(filepath.Join(uploadDir, request.Filename))
	if err != nil {
		log.Printf("Error removing file from filesystem: %v", err)
		// We don't return an error here because the file has been removed from the database
	}

	w.WriteHeader(http.StatusOK)
}

func starHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Username string `json:"username"`
		Filename string `json:"filename"`
		Action   string `json:"action"` // "star" or "unstar"
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the file ID
	var fileID int
	err = db.QueryRow("SELECT id FROM files WHERE name = ?", request.Filename).Scan(&fileID)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	if request.Action == "star" {
		_, err = db.Exec("INSERT OR IGNORE INTO stars (file_id, username) VALUES (?, ?)", fileID, request.Username)
	} else if request.Action == "unstar" {
		_, err = db.Exec("DELETE FROM stars WHERE file_id = ? AND username = ?", fileID, request.Username)
	} else {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func starredFilesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	query := `
        SELECT f.name, f.description, f.username,
               (SELECT COUNT(*) FROM stars WHERE file_id = f.id) as star_count
        FROM files f
        JOIN stars s ON f.id = s.file_id
        WHERE s.username = ?
    `
	rows, err := db.Query(query, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var name, description, fileUsername string
		var starCount int
		err := rows.Scan(&name, &description, &fileUsername, &starCount)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		files = append(files, map[string]interface{}{
			"name":        name,
			"url":         fmt.Sprintf("http://%s/files/%s", r.Host, name),
			"description": description,
			"username":    fileUsername,
			"starCount":   starCount,
			"isStarred":   true,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Username        string `json:"username"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Retrieve hashed password from the database
	var hashedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", request.Username).Scan(&hashedPassword)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Compare current password with the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(request.CurrentPassword))
	if err != nil {
		http.Error(w, "Incorrect current password", http.StatusUnauthorized)
		return
	}

	// Generate hash for the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update password in the database
	_, err = db.Exec("UPDATE users SET password = ? WHERE username = ?", string(hashedNewPassword), request.Username)
	if err != nil {
		http.Error(w, "Failed to reset password", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
