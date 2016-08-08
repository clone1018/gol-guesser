package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type WebServer struct {
	Port string
}

func (ws *WebServer) Start() {

	r := mux.NewRouter()
	r.HandleFunc("/", ws.HomeHandler)
	r.HandleFunc("/guess", ws.GuessHandler)
	log.Fatal(http.ListenAndServe(":"+ws.Port, r))
}

func (ws *WebServer) HomeHandler(w http.ResponseWriter, r *http.Request) {

}

func (ws *WebServer) GuessHandler(w http.ResponseWriter, r *http.Request) {
	guess := r.URL.Query().Get("password")
	ciphers := r.URL.Query().Get("ciphers")

	var allCiphers = false
	if ciphers == "all" {
		allCiphers = true
	}

	attempts := AttemptGuess(guess, allCiphers)

	b, err := json.Marshal(attempts)
	if err != nil {
		log.Println(err)
		w.Write([]byte("Fatal untracked error"))
		return
	}

	w.Header().Add("Cache-Control", "public, max-age=25565")
	w.Header().Add("Content-Type", "application/json; charset=utf-8")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Write(b)

}
