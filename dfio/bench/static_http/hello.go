// Building:
// go build -o hello-golang hello.go
// Running with 1 core:
// GOMAXPROCS=1 ./hello-golang
// Running with all cores
// ./hello-golang
package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, world!")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
