package routes

import (
	"course-microservice/pkg/course"
	"github.com/gorilla/mux"
)

func RegisterCourseRoutes(r *mux.Router) {
	r.HandleFunc("/courses", (&course.Course{}).Create).Methods("POST")
	r.HandleFunc("/courses", course.GetAll).Methods("GET")
	r.HandleFunc("/courses/{id}", (&course.Course{}).Update).Methods("PUT")
	r.HandleFunc("/courses/{id}", course.Delete).Methods("DELETE")
	r.HandleFunc("/courses/{id}/enroll", course.Enroll).Methods("POST")
}
