package main

import (
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"user-microservice/pkg/initial"
	"user-microservice/pkg/middleware"
	"user-microservice/pkg/routes"
)

func init() {
	initial.LoadEnvComp()
	var err error
	_, err = initial.ConnDB()
	if err != nil {
		panic(err)
	}
	err = initial.CreateUser()
	if err != nil {
		panic(err)
	}
	initial.ConnRedis()
}

func main() {
	r := mux.NewRouter()
	routes.Register(r)
	meRouter := r.PathPrefix("/api").Subrouter()
	meRouter.Use(middleware.AuthMiddleware)
	routes.Me(meRouter)
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}
