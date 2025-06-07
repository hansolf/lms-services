package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"user-microservice/pkg/email"
	"user-microservice/pkg/initial"
	"user-microservice/pkg/middleware"
)

type RegisterReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func ConstructorReg() *RegisterReq {
	return &RegisterReq{}
}
func (reg *RegisterReq) SendEmail(w http.ResponseWriter, r *http.Request) {
	err := json.NewDecoder(r.Body).Decode(&reg)
	if err != nil {
		http.Error(w, "Не удалось преобразовать json в структуру", http.StatusInternalServerError)
	}
	rdb := initial.ConnRedis()
	code := generateCode()
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Проблема с хэшированием кода", http.StatusInternalServerError)
		return
	}
	err = rdb.Set(context.Background(), reg.Email, string(hash), time.Minute*10).Err()
	if err != nil {
		http.Error(w, "Не удалось сохранить код", http.StatusInternalServerError)
		return
	}
	emailD := email.EmailData{
		Code: code,
	}
	htmlS, err := emailD.GenerateEmailHTML("EmailCode.html")
	if err != nil {
		http.Error(w, "Не удалось перевести в строку", http.StatusBadRequest)
		return
	}
	to := []string{reg.Email}
	topic := "Новое уведомление от LMS"
	err = email.SendEmail(to, topic, htmlS)
	if err != nil {
		http.Error(w, "Не удалось отправить письмо", http.StatusBadRequest)
		return
	}
}

type VerifyReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

func ConstructorVerifyReg() *VerifyReq {
	return &VerifyReq{}
}

func (vr *VerifyReq) Register(w http.ResponseWriter, r *http.Request) {
	err := json.NewDecoder(r.Body).Decode(&vr)
	if err != nil {
		http.Error(w, "Не удалось декодировать", http.StatusInternalServerError)
		return
	}
	rdb := initial.ConnRedis()
	val, err := rdb.Get(context.Background(), vr.Email).Result()
	if err != nil {
		http.Error(w, "Не удалось найти код", http.StatusInternalServerError)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(val), []byte(vr.Code))
	if err != nil {
		http.Error(w, "Код неверный", http.StatusBadRequest)
		return
	}
	conn, _ := initial.ConnDB()
	defer conn.Close(context.Background())
	var exist int
	err = conn.QueryRow(context.Background(), "SELECT COUNT(*) FROM users WHERE email = $1", vr.Email).Scan(&exist)
	if err != nil {
		http.Error(w, "Ошибка проверки пользователя", http.StatusInternalServerError)
		return
	}
	if exist != 0 {
		http.Error(w, "Пользователь уже существует", http.StatusBadRequest)
		return
	}
	pass, err := bcrypt.GenerateFromPassword([]byte(vr.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Не удалось хэшировать пароль", http.StatusInternalServerError)
		return
	}
	var (
		id, name, surname, vuz, kaferda, fakultet, roleUser sql.NullString
	)
	err = conn.QueryRow(context.Background(),
		`INSERT INTO users (email, passwordhash, role)
	 VALUES ($1, $2, $3)
	 RETURNING id, nameuser, surname, vuz, kaferda, fakultet, role`,
		vr.Email, string(pass), "Студент").
		Scan(&id, &name, &surname, &vuz, &kaferda, &fakultet, &roleUser)
	if err != nil {
		fmt.Println("Ошибка:", err)
		http.Error(w, "Ошибка создания пользователя", http.StatusInternalServerError)
		return
	}
	rdb.Del(context.Background(), vr.Email)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":      id,
		"name":     name,
		"surname":  surname,
		"email":    vr.Email,
		"role":     roleUser,
		"vuz":      vuz,
		"kafedra":  kaferda,
		"fakultet": fakultet,
		"exp":      time.Now().Add(time.Hour * 30).Unix(),
	})
	tokenstring, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		http.Error(w, "не удалось создать токен", http.StatusNotFound)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenstring,
		Path:     "/",
		Expires:  time.Now().Add(time.Hour * 30),
		Secure:   false,
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
}

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func ConstructorLogin() *LoginReq {
	return &LoginReq{}
}
func (lr *LoginReq) Login(w http.ResponseWriter, r *http.Request) {
	err := json.NewDecoder(r.Body).Decode(&lr)
	if err != nil {
		http.Error(w, "Не удалось декодировать", http.StatusInternalServerError)
		return
	}
	conn, _ := initial.ConnDB()
	var pass string
	err = conn.QueryRow(context.Background(), "SELECT passwordHash FROM users WHERE email = $1", lr.Email).Scan(&pass)
	if err != nil {
		http.Error(w, "Не удалось найти пользователя", http.StatusBadRequest)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(pass), []byte(lr.Password))
	if err != nil {
		http.Error(w, "Неправильный пароль", http.StatusBadRequest)
		return
	}
	var (
		id, name, surname, vuz, kafedra, fakultet, roleUser *string
	)
	err = conn.QueryRow(context.Background(), "SELECT id, nameUser, surname,vuz,kaferda,fakultet,role FROM users WHERE email = $1", lr.Email).Scan(&id, &name, &surname, &vuz, &kafedra, &fakultet, &roleUser)
	if err != nil {
		http.Error(w, "Не удалось найти пользователя", http.StatusBadRequest)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":      id,
		"name":     name,
		"surname":  surname,
		"email":    lr.Email,
		"role":     roleUser,
		"vuz":      vuz,
		"kafedra":  kafedra,
		"fakultet": fakultet,
		"exp":      time.Now().Add(time.Hour * 30).Unix(),
	})
	tokenstring, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		http.Error(w, "не удалось создать токен", http.StatusNotFound)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenstring,
		Path:     "/",
		Expires:  time.Now().Add(time.Hour * 30),
		Secure:   false,
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
		MaxAge:   -1,
		Secure:   false,
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
}
func Me(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.GetUserInfoFromContext(r)
	if !ok {
		http.Error(w, "Пользователь не авторизован", http.StatusUnauthorized)
		return
	}
	if user.Role != "Преподаватель" && user.Role != "Администратор" {
		response := struct {
			Name     string `json:"name"`
			Role     string `json:"role"`
			Surname  string `json:"surname"`
			Fakultet string `json:"fakultet"`
			Vuz      string `json:"vuz"`
			Email    string `json:"email"`
		}{
			Name:     user.Name,
			Role:     user.Role,
			Surname:  user.Surname,
			Fakultet: user.Fakultet,
			Vuz:      user.Vuz,
			Email:    user.Email,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		response := struct {
			Name    string `json:"name"`
			Role    string `json:"role"`
			Surname string `json:"surname"`
			Kafedra string `json:"kafedra"`
			Vuz     string `json:"vuz"`
			Email   string `json:"email"`
		}{
			Name:    user.Name,
			Role:    user.Role,
			Surname: user.Surname,
			Kafedra: user.Kafedra,
			Vuz:     user.Vuz,
			Email:   user.Email,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

type ReqToVerify struct {
	Name    string `json:"name"`
	Surname string `json:"surname"`
	Vuz     string `json:"vuz"`
	Kafedra string `json:"kafedra"`
}

func Constructor() *ReqToVerify {
	return &ReqToVerify{}
}

func (v *ReqToVerify) SendVerTeach(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.GetUserInfoFromContext(r)
	if !ok {
		http.Error(w, "Не авторизован", http.StatusUnauthorized)
		return
	}
	if user.Role == "Преподаватель" {
		http.Error(w, "Вы уже преподаватель", http.StatusNotFound)
		return
	}
	err := json.NewDecoder(r.Body).Decode(&v)
	if err != nil {
		http.Error(w, "Не удалось декодировать", http.StatusBadRequest)
		return
	}
	if strings.Contains(v.Name, "|") && strings.Contains(user.Email, "|") {
		http.Error(w, "Форма содержит запрещенные символы", http.StatusBadRequest)
		return
	}
	rdb := initial.ConnRedis()
	val := user.Email + "|" + v.Name + "|" + v.Surname + "|" + v.Vuz + "|" + v.Kafedra
	strID := user.ID
	err = rdb.Set(context.Background(), strID, val, 7*60*24*time.Minute).Err()
	if err != nil {
		http.Error(w, "Не удалось установить ключи REDIS", http.StatusBadRequest)
		return
	}
	//'СПбГЭУ', 'НИУ ИТМО', 'СПбПУ Петра Великого'
	emailD := email.EmailData{
		NameTeacher:       v.Name,
		SecondNameTeacher: v.Surname,
		Vuz:               v.Vuz,
		Kafedra:           v.Kafedra,
		VerifyLink:        "http://localhost:8080/api/verifyteach/" + strID,
	}
	if v.Vuz == "СПбГЭУ" {
		var htmlS string
		htmlS, err = emailD.GenerateEmailHTML("VerifyTeacher.html")
		if err != nil {
			http.Error(w, "Не удалось перевести html страницу в строку", http.StatusBadRequest)
			return
		}
		to := []string{os.Getenv("UNECON_ADMIN")}
		subject := "Уведомление от LMS"
		err = email.SendEmail(to, subject, htmlS)
		if err != nil {
			http.Error(w, "Не удалось отправить на почту админа", http.StatusBadRequest)
			return
		}
	}

	if v.Vuz == "СПбПУ Петра Великого" {
		var htmlS string
		htmlS, err = emailD.GenerateEmailHTML("VerifyTeacher.html")
		if err != nil {
			http.Error(w, "Не удалось перевести html страницу в строку", http.StatusBadRequest)
			return
		}
		to := []string{os.Getenv("SPBPU_ADMIN")}
		subject := "Уведомление от LMS"
		err = email.SendEmail(to, subject, htmlS)
		if err != nil {
			http.Error(w, "Не удалось отправить на почту админа", http.StatusBadRequest)
			return
		}
	}

	if v.Vuz == "НИУ ИТМО" {
		var htmlS string
		htmlS, err = emailD.GenerateEmailHTML("VerifyTeacher.html")
		if err != nil {
			http.Error(w, "Не удалось перевести html страницу в строку", http.StatusBadRequest)
			return
		}
		to := []string{os.Getenv("ITMO_ADMIN")}
		subject := "Уведомление от LMS"
		err = email.SendEmail(to, subject, htmlS)
		if err != nil {
			http.Error(w, "Не удалось отправить на почту админа", http.StatusBadRequest)
			return
		}
	}
}

func VerifyTeacher(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_URL"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
	val, err := rdb.Get(context.Background(), userID).Result()
	if err != nil {
		http.Error(w, "Не удалось получить данные из Redis", http.StatusBadRequest)
		return
	}
	data := strings.Split(val, "|")
	if len(data) < 5 {
		http.Error(w, "Недостаточно данных в Redis", http.StatusInternalServerError)
		return
	}

	conn, err := initial.ConnDB()
	if err != nil {
		http.Error(w, "Ошибка подключения к БД", http.StatusInternalServerError)
		return
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(context.Background(),
		`UPDATE users SET 
			vuz = $4, 
			kaferda = $5, 
			role = $6
		WHERE id = $7`,
		data[3], data[4], "Преподаватель", userID)
	if err != nil {
		http.Error(w, "Не удалось обновить пользователя", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type RespToCh struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func ConstructorPass() *RespToCh {
	return &RespToCh{}
}

func (c *RespToCh) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.GetUserInfoFromContext(r)
	if !ok {
		http.Error(w, "Не авторизован", http.StatusUnauthorized)
		return
	}
	conn, _ := initial.ConnDB()
	var password string
	err := conn.QueryRow(context.Background(), "SELECT passwordhash FROM users WHERE id = $1", user.ID).Scan(&password)
	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusInternalServerError)
		return
	}
	err = json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		http.Error(w, "Ошибка с декодированием", http.StatusBadRequest)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(c.OldPassword))
	if err != nil {
		http.Error(w, "Неверный пароль", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(c.NewPassword), 10)
	if err != nil {
		http.Error(w, "Ошибка с хэшерованием", http.StatusBadRequest)
		return
	}
	_, err = conn.Exec(context.Background(), "UPDATE users SET passwordhash = $1 WHERE id = $2", string(hash), user.ID)
	if err != nil {
		http.Error(w, "Не удалось сменить пароль", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type UserUpdateRequest struct {
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Vuz      string `json:"vuz"`
	Kafedra  string `json:"kafedra"`
	Fakultet string `json:"fakultet"`
}

func UpdateMe(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.GetUserInfoFromContext(r)
	if !ok {
		http.Error(w, "Не авторизован", http.StatusUnauthorized)
		return
	}

	var update UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Не удалось задекодировать", http.StatusBadRequest)
		return
	}
	conn, err := initial.ConnDB()
	if err != nil {
		http.Error(w, "Ошибка подключения к БД", http.StatusInternalServerError)
		return
	}
	defer conn.Close(context.Background())
	IDint, _ := strconv.Atoi(user.ID)
	var (
		name, surname, vuz, kafedra, fakultet sql.NullString
	)
	err = conn.QueryRow(context.Background(),
		"SELECT nameuser, surname, vuz, kaferda, fakultet FROM users WHERE id = $1", IDint).
		Scan(&name, &surname, &vuz, &kafedra, &fakultet)
	if err != nil {
		http.Error(w, "Не удалось найти пользователя"+user.ID, http.StatusNotFound)
		return
	}

	if update.Name == "" && name.Valid {
		update.Name = name.String
	}
	if update.Surname == "" && surname.Valid {
		update.Surname = surname.String
	}
	if update.Vuz == "" && vuz.Valid {
		update.Vuz = vuz.String
	}
	if update.Kafedra == "" && kafedra.Valid {
		update.Kafedra = kafedra.String
	}
	if update.Fakultet == "" && fakultet.Valid {
		update.Fakultet = fakultet.String
	}

	_, err = conn.Exec(context.Background(),
		`UPDATE users SET nameuser=$1, surname=$2, vuz=$3, kaferda=$4, fakultet=$5 WHERE id=$6`,
		update.Name, update.Surname, update.Vuz, update.Kafedra, update.Fakultet, user.ID)
	if err != nil {
		http.Error(w, "Ошибка при сохранении", http.StatusInternalServerError)
		return
	}

	resp := middleware.UserInfo{
		ID:       user.ID,
		Name:     update.Name,
		Surname:  update.Surname,
		Email:    user.Email,
		Role:     user.Role,
		Vuz:      update.Vuz,
		Kafedra:  update.Kafedra,
		Fakultet: update.Fakultet,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func generateCode() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}
