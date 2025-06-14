package initial

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"log"
	"os"
)

func LoadEnvComp() {
	err := godotenv.Load()
	if err != nil {
		log.Println(".env файл не найден, используются переменные окружения из системы")
	}
}

func ConnDB() (*pgx.Conn, error) {
	conn, err := pgx.Connect(context.Background(), os.Getenv("DB_URL1"))
	if err != nil {
		fmt.Println("Не удалось подключиться к бд ", err)
	}
	return conn, err
}

func CreateCourse() error {
	conn, _ := ConnDB()
	defer conn.Close(context.Background())
	createCourse := `CREATE TABLE IF NOT EXISTS course (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    category TEXT NOT NULL,
    idTeacher INTEGER NOT NULL
)`
	_, err := conn.Exec(context.Background(), createCourse)
	if err != nil {
		return fmt.Errorf("Ошибка создания курса бд %v", err)
	}
	createUserC := `CREATE TABLE IF NOT EXISTS usercourse (
    id SERIAL PRIMARY KEY,
    userID INTEGER NOT NULL,
    courseID INTEGER NOT NULL,
    status TEXT NOT NULL
)`
	_, err = conn.Exec(context.Background(), createUserC)
	if err != nil {
		return fmt.Errorf("Ошибка создания usercourse %v", err)
	}
	return nil
}
