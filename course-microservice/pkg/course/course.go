package course

import (
	"context"
	"course-microservice/pkg/initial"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hansolf/middleware/middlewarelms"
	"net/http"
	"strconv"
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
	_, err = conn.Exec(context.Background(), "INSERT INTO course (title, description, author, category, idTeacher) VALUES ($1, $2, $3, $4)", c.Title, c.Description, c.Author, c.Category, user.ID)
	if err != nil {
		http.Error(w, "Не удалось создать таблицу курса", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)

	//Kafka search
}

func GetAll(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	conn, err := initial.ConnDB()
	if err != nil {
		http.Error(w, "Ошибка подключения к БД", http.StatusInternalServerError)
		return
	}
	defer conn.Close(ctx)

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

//заполнить GetOne после уроков

/*func GetOne(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "ID курса не указан", http.StatusBadRequest)
		return
	}
}*/

func (c *Course) Update(w http.ResponseWriter, r *http.Request) {
	user, ok := middlewarelms.GetUserInfoFromContext(r)
	if !ok {
		http.Error(w, "Не авторизован", http.StatusUnauthorized)
		return
	}
	if user.Role != "Администратор" && user.Role != "Преподаватель" {
		http.Error(w, "Доступ запрещен", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		http.Error(w, "Не удалось декодировать", http.StatusInternalServerError)
		return
	}
	conn, _ := initial.ConnDB()
	defer conn.Close(context.Background())
	_, err = conn.Exec(context.Background(), "UPDATE course SET title=$1,description=$2, category=$3,author=$4 WHERE id = $5", c.Title, c.Description, c.Category, c.Author, id)
	if err != nil {
		http.Error(w, "Не удалось обновить курс", http.StatusInternalServerError)
		return
	}
	//Kafka
	w.WriteHeader(http.StatusOK)
}

func Delete(w http.ResponseWriter, r *http.Request) {
	user, ok := middlewarelms.GetUserInfoFromContext(r)
	if !ok {
		http.Error(w, "Не авторизован", http.StatusUnauthorized)
		return
	}
	if user.Role != "Администратор" {
		http.Error(w, "Доступ запрещен", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]
	conn, _ := initial.ConnDB()
	defer conn.Close(context.Background())
	_, err := conn.Exec(context.Background(), "DELETE FROM course WHERE id = $1", id)
	if err != nil {
		http.Error(w, "Не удалось удалить курс", http.StatusInternalServerError)
		return
	}
	//Добавить kafka
	w.WriteHeader(http.StatusOK)
}

func Enroll(w http.ResponseWriter, r *http.Request) {
	user, ok := middlewarelms.GetUserInfoFromContext(r)
	if !ok {
		http.Error(w, "Не авторизован", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "ID курса не указан", http.StatusBadRequest)
		return
	}

	conn, err := initial.ConnDB()
	if err != nil {
		http.Error(w, "Ошибка подключения к БД", http.StatusInternalServerError)
		return
	}
	defer conn.Close(context.Background())

	userID, err := strconv.Atoi(user.ID)
	if err != nil {
		http.Error(w, "Некорректный ID пользователя", http.StatusBadRequest)
		return
	}
	courseID, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Некорректный ID курса", http.StatusBadRequest)
		return
	}

	var exists bool
	err = conn.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM usercourse WHERE user_id=$1 AND course_id=$2)",
		userID, courseID).Scan(&exists)
	if err != nil {
		http.Error(w, "Ошибка проверки записи", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "Пользователь уже записан на курс", http.StatusConflict)
		return
	}
	_, err = conn.Exec(context.Background(),
		"INSERT INTO usercourse (user_id, course_id, status) VALUES ($1, $2, $3)",
		userID, courseID, "enrolled")
	if err != nil {
		http.Error(w, "Ошибка при записи на курс", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Пользователь успешно записан на курс"))
}
