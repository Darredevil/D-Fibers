package main

import (
	"fmt"
	"log"
	"github.com/valyala/fasthttp"
)

func main() {
	h := requestHandler
	if err := fasthttp.ListenAndServe("0.0.0.0:8080", h); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "Hello, world!")
}