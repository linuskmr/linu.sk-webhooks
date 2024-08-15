package main

import (
	"log"
	"net/http"
	"strings"
)

func main() {
	addr := ":8010"
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/github", Github)
	log.Println("Listening on", addr)
	http.ListenAndServe(addr, globalMiddleware(http.DefaultServeMux))
}

func globalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "net/http go")
		next.ServeHTTP(w, r)
	})
}

func handleIndex(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(strings.ReplaceAll(`<html>
	<head>
		<meta charset="UTF-8">
    	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	</head>
	<body">
		<pre style="text-align: center; margin: 3em 0;">
		<b>webhooks.linu.sk</b><br>
		Nothing to see here, except the <a href="https://github.com/linuskmr/webhooks.linu.sk">code</a>.
		</pre>
	</body>
	</html>`, "\t", "")))
}