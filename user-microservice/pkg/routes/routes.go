package routes

import (
	"github.com/gorilla/mux"
	"user-microservice/pkg/auth"
)

func Register(h *mux.Router) {
	reg := auth.ConstructorReg()
	ver := auth.ConstructorVerifyReg()
	login := auth.ConstructorLogin()
	h.HandleFunc("/api/send", reg.SendEmail).Methods("POST")
	h.HandleFunc("/api/verify", ver.Register).Methods("POST")
	h.HandleFunc("/api/login", login.Login).Methods("POST")
	h.HandleFunc("/api/logout", auth.Logout).Methods("DELETE")
	h.HandleFunc("/api/verifyteach/{id}", auth.VerifyTeacher)
}
func Me(h *mux.Router) {
	ver := auth.Constructor()
	change := auth.ConstructorPass()
	h.HandleFunc("/me", auth.Me).Methods("GET")
	h.HandleFunc("/me/update", auth.UpdateMe).Methods("POST")
	h.HandleFunc("/me/teacher", ver.SendVerTeach).Methods("POST")
	h.HandleFunc("/me/changepass", change.ChangePassword).Methods("POST")
}
