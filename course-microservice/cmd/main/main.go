package main

import (
	"course-microservice/pkg/initial"
	routes2 "course-microservice/pkg/routes"
	"github.com/gorilla/mux"
	"github.com/hansolf/middleware/middlewarelms"
	"log"
	"net/http"
)

func init() {
	initial.LoadEnvComp()
	var err error
	_, err = initial.ConnDB()
	if err != nil {
		panic(err)
	}
	err = initial.CreateCourse()
	if err != nil {
		panic(err)
	}
}

func main() {
	r := mux.NewRouter()
	CRouter := r.PathPrefix("/api").Subrouter()
	CRouter.Use(middlewarelms.AuthMiddleware)
	routes2.RegisterCourseRoutes(CRouter)
	err := http.ListenAndServe(":8081", r)
	if err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}
