package initial

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
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
	conn, err := pgx.Connect(context.Background(), os.Getenv("DB_URL"))
	if err != nil {
		return nil, fmt.Errorf("Не удалось подключиться к базе данных: %w", err)
	}
	return conn, err
}

func CreateUser() error {
	conn, err := ConnDB()
	if err != nil {
		return fmt.Errorf("Не удалось подключиться к бд: %v", err)
	}
	defer conn.Close(context.Background())
	createTable := `
	CREATE TABLE IF NOT EXISTS users (
	  id SERIAL PRIMARY KEY,
	  nameUser TEXT,
	  surname TEXT,
	  vuz	  TEXT,
	  kaferda TEXT,
	  fakultet TEXT,
	  email  TEXT UNIQUE NOT NULL,
	  passwordHash TEXT,
	  role TEXT	
	);
`
	_, err = conn.Exec(context.Background(), createTable)
	if err != nil {
		return fmt.Errorf("Не удалось создать таблицу users: %v", err)
	}
	return nil
}
func ConnRedis() *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_URL"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
	return rdb
}
