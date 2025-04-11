package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

// EmailCheck represents the request and response structure
type EmailCheck struct {
	Email       string `json:"email"`
	Compromised bool   `json:"compromised"`
	CheckedAt   string `json:"checked_at,omitempty"`
}

var (
	db          *sql.DB
	redisClient *redis.Client
	ctx         = context.Background()
)

func main() {
	// Initialize database connection
	dbHost := getEnvOrDefault("DB_HOST", "postgres")
	dbUser := getEnvOrDefault("DB_USER", "postgres")
	dbPassword := getEnvOrDefault("DB_PASSWORD", "postgres")
	dbName := getEnvOrDefault("DB_NAME", "breachdb")
	dbPort := getEnvOrDefault("DB_PORT", "5432")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test connection
	if err = db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	// Initialize Redis connection
	redisHost := getEnvOrDefault("REDIS_HOST", "redis")
	redisPort := getEnvOrDefault("REDIS_PORT", "6379")
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	redisClient = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	// Test Redis connection
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Initialize database schema
	initDB()

	// Setup router
	r := mux.NewRouter()
	r.HandleFunc("/api/check", checkEmailHandler).Methods("POST")
	r.HandleFunc("/api/health", healthCheckHandler).Methods("GET")

	// Middleware
	r.Use(corsMiddleware)
	r.Use(loggingMiddleware)
	r.Use(securityHeadersMiddleware)

	port := getEnvOrDefault("API_PORT", "8080")
	serverAddr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("Server is running on %s", serverAddr)
	log.Fatal(http.ListenAndServe(serverAddr, r))
}

func initDB() {
	// Create tables if they don't exist
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS compromised_emails (
			id SERIAL PRIMARY KEY,
			email_hash VARCHAR(64) NOT NULL UNIQUE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_email_hash ON compromised_emails(email_hash);
		
		CREATE TABLE IF NOT EXISTS check_history (
			id SERIAL PRIMARY KEY,
			email_hash VARCHAR(64) NOT NULL UNIQUE,
			checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			was_compromised BOOLEAN NOT NULL
		);
	`)
	if err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// Seed some sample compromised emails for testing
	sampleEmails := []string{
		"compromised@example.com",
		"test.breach@gmail.com",
		"hacked@yahoo.com",
	}

	for _, email := range sampleEmails {

		hash := hashEmail(email)
		// Insert into DB
		_, err := db.Exec(`
			INSERT INTO compromised_emails (email_hash) 
			VALUES ($1) 
			ON CONFLICT (email_hash) DO NOTHING`,
			hash)
		if err != nil {
			log.Printf("Warning: Failed to seed email %s: %v", email, err)
		}
	}

}

func checkEmailHandler(w http.ResponseWriter, r *http.Request) {
	var emailCheck EmailCheck

	// Parse JSON request
	err := json.NewDecoder(r.Body).Decode(&emailCheck)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if emailCheck.Email == "" {
		http.Error(w, "Email address is required", http.StatusBadRequest)
		return
	}

	// Hash the email
	hashed := hashEmail(emailCheck.Email)
	cacheKey := fmt.Sprintf("email_check:%s", hashed)

	// Check cache first
	cachedResult, err := redisClient.Get(ctx, cacheKey).Result()

	if err == nil {
		// Found in cache
		var result EmailCheck
		if err := json.Unmarshal([]byte(cachedResult), &result); err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "HIT")
			json.NewEncoder(w).Encode(result)
			return
		}
	}

	// Not found in cache or error, check database
	compromised := isEmailCompromised(emailCheck.Email)

	// Create result
	result := EmailCheck{
		Email:       emailCheck.Email,
		Compromised: compromised,
		CheckedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	// Store in cache for 1 hour
	resultJSON, _ := json.Marshal(result)
	redisClient.Set(ctx, cacheKey, resultJSON, time.Hour)

	// Log this check in history
	logEmailCheck(emailCheck.Email, compromised)

	// Return result
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Cache", "MISS")
	json.NewEncoder(w).Encode(result)
}

func isEmailCompromised(email string) bool {
	// Hash the email for security (we don't store plain emails)
	emailHash := hashEmail(email)

	// Check if email hash exists in database
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM compromised_emails WHERE email_hash = $1)`
	err := db.QueryRow(query, emailHash).Scan(&exists)

	if err != nil {
		log.Printf("Database query error: %v", err)
		return false
	}

	return exists
}

func logEmailCheck(email string, wasCompromised bool) {
	// Hash email for privacy
	hash, _ := bcrypt.GenerateFromPassword([]byte(email), bcrypt.DefaultCost)
	emailHash := string(hash)

	// Insert check record
	_, err := db.Exec(
		`INSERT INTO check_history (email_hash, was_compromised) VALUES ($1, $2)`,
		emailHash, wasCompromised,
	)

	if err != nil {
		log.Printf("Failed to log email check: %v", err)
	}
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Check database connection
	dbErr := db.Ping()

	// Check Redis connection
	_, redisErr := redisClient.Ping(ctx).Result()

	health := map[string]interface{}{
		"status":  "up",
		"db":      dbErr == nil,
		"redis":   redisErr == nil,
		"time":    time.Now().UTC().Format(time.RFC3339),
		"version": "1.0.0",
	}

	if dbErr != nil || redisErr != nil {
		health["status"] = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// Middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf(
			"%s %s %s %s",
			r.RemoteAddr,
			r.Method,
			r.RequestURI,
			time.Since(start),
		)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func hashEmail(email string) string {
	h := sha256.New()
	h.Write([]byte(email))
	return hex.EncodeToString(h.Sum(nil))
}
