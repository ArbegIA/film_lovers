package main

// Выполнение запроса SELECT для получения данных из таблицы users
rows, err := db.Query("SELECT * FROM users")
if err != nil {
panic(err)
}
defer rows.Close()

// Итерирование по результатам и вывод каждой строки
for rows.Next() {
var id int
var username string
var password string

// Сканирование значений из текущей строки в переменные
if err := rows.Scan(&id, &username, &password); err != nil {
panic(err)
}

// Вывод значений строки
fmt.Printf("ID: %d, Username: %s, Password: %s\n", id, username, password)
}

// Проверка наличия ошибок после итерации по результатам
if err := rows.Err(); err != nil {
panic(err)
}
