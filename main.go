package main

import (
	"log"
	"net/http"
)

func main() {
	addr := ":8010"
	http.HandleFunc("/github", Github)
	log.Println("Listening on", addr)
	http.ListenAndServe(addr, nil)
}
