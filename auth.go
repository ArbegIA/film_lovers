package main

import (
	"database/sql"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"time"
)

type User struct {
	Username string
	Password string
}

var db *sql.DB

func main() {
	connStr := "host=212.113.123.129 user=gen_user password=76543210Base dbname=default_db sslmode=disable"

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	// Проверка соединения
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	SelectUsers := `SELECT * FROM users`

	result, err := db.Exec(SelectUsers)
	if err != nil {
		panic(err)
	}
	fmt.Println("Запрос в базу данных выполнен")

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Количество затронутых строк: %d\n", rowsAffected)

	fmt.Println("Успешное подключение к серверу PostgreSQL")

	defer db.Close()

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/protected", protectedEndpoint)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	// Получаем логин и пароль из тела запроса
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Проверяем, что логин не занят
	if checkUserExists(username) {
		http.Error(w, "Логин уже занят", http.StatusBadRequest)
		return
	}

	// Создаем нового пользователя
	user := User{
		Username: username,
		Password: password,
	}

	// Сохраняем пользователя в базе данных
	_, err := db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", user.Username, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Возвращаем успешный ответ
	w.WriteHeader(http.StatusCreated)
}

func authenticateUser(username, password string) bool {
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = $1", username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false // Пользователь не найден
		}
		log.Fatal(err)
	}

	return storedPassword == password
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	// Получаем логин и пароль из тела запроса
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Проверяем логин и пароль
	if !authenticateUser(username, password) {
		http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
		return
	}

	// Создаем токен
	token := jwt.New(jwt.SigningMethodHS256)

	// Устанавливаем набор клеймов для токена
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Подписываем токен с использованием секретного ключа
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Возвращаем токен в ответе
	w.Write([]byte(tokenString))
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не разрешен", http.StatusMethodNotAllowed)
		return
	}

	// Получаем заголовок с токеном авторизации
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Требуется заголовок Authorization", http.StatusUnauthorized)
		return
	}

	// Извлекаем токен из заголовка
	tokenString := authHeader[len("Bearer "):]

	// Проверяем и разбираем токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Неподдерживаемый алгоритм подписи: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Проверяем, что токен является действительным и не истек
	if !token.Valid {
		http.Error(w, "Недействительный токен авторизации", http.StatusUnauthorized)
		return
	}

	// Получаем имя пользователя из токена
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Неверный формат токена", http.StatusUnauthorized)
		return
	}

	username, ok := claims["username"].(string)
	if !ok {
		http.Error(w, "Неверный формат токена", http.StatusUnauthorized)
		return
	}

	// Возвращаем ответ с защищенным ресурсом
	fmt.Fprintf(w, "Защищенный ресурс для пользователя: %s", username)
}

func checkUserExists(username string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", username).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}
	return count > 0
}
