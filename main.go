package main

import (
	"nidan-kai/nidankai"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		panic(err)
	}

	nidankai.Run()
}
