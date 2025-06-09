package course

import (
	"context"
	"course-microservice/pkg/initial"
	"encoding/json"
	"fmt"
	"github.com/hansolf/middleware/middlewarelms"
	"net/http"
)

type Course struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Author      string `json:"author"`
	Category    string `json:"category"`
}

func (c *Course) Create(w http.ResponseWriter, r *http.Request) {
	user, ok := middlewarelms.GetUserInfoFromContext(r)
	if !ok {
		http.Error(w, "Не авторизован", http.StatusUnauthorized)
		return
	}
	if user.Role != "Администратор" && user.Role != "Преподаватель" {
		http.Error(w, "Доступ запрещен", http.StatusForbidden)
		return
	}
	c.Author = fmt.Sprintf("%v %v", user.Name, user.Surname)
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		http.Error(w, "Проблема с декодированием", http.StatusInternalServerError)
		return
	}
	conn, _ := initial.ConnDB()
	defer conn.Close(context.Background())
	_, err = conn.Exec(context.Background(), "INSERT INTO course (title, description, author, category) VALUES ($1, $2, $3, $4)", c.Title, c.Description, c.Author, c.Category)
	if err != nil {
		http.Error(w, "Не удалось создать таблицу курса", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

func GetAll(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	conn, err := initial.ConnDB()
	if err != nil {
		http.Error(w, "Ошибка подключения к БД", http.StatusInternalServerError)
		return
	}
	defer conn.Close(ctx)

	// Получаем все курсы
	rows, err := conn.Query(ctx, "SELECT title, description,author, category FROM course")
	if err != nil {
		http.Error(w, "Не удалось получить курсы", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var courses []Course
	for rows.Next() {
		var c Course
		if err := rows.Scan(&c.Title, &c.Description, &c.Author, &c.Category); err != nil {
			http.Error(w, "Ошибка чтения курса", http.StatusInternalServerError)
			return
		}
		courses = append(courses, c)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(courses)
}
