package email

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"os"
)

type EmailRequest struct {
	ToAddress string `json:"to_addr"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
}

type EmailData struct {
	Code              string `json:"code"`
	NameTeacher       string `json:"name_teacher"`
	SecondNameTeacher string `json:"second_name_teacher"`
	Vuz               string `json:"vuz"`
	Kafedra           string `json:"kafedra"`
	VerifyLink        string `json:"verify_link"`
}

func SendEmail(to []string, subject, html string) error {
	auth := smtp.PlainAuth("", os.Getenv("EMAIL"), os.Getenv("EMAILPASS"), os.Getenv("SMTP"))
	headers := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";"
	message := "Subject: " + subject + "\n" + headers + "\n\n" + html
	return smtp.SendMail(os.Getenv("SMTP_ADDR"), auth, os.Getenv("EMAIL"), to, []byte(message))
}

func (data *EmailData) GenerateEmailHTML(html string) (string, error) {
	tmpl, err := template.New("Email").ParseFiles(os.Getenv("PATH_TO_HTML") + html)
	if err != nil {
		return "", fmt.Errorf("ошибка парсинга шаблона %s: %w", os.Getenv("PATH_TO_HTML")+html, err)
	}
	var buf bytes.Buffer
	if err = tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
