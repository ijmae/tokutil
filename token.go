package main

import (
	"fmt"

	tokenpb "tdm/tokenutility/protobuf/token"
)

func main() {
}

func Encode[TokenData models.AccessToken | models.RefreshToken](decoded TokenData) string {
	fmt.Println(configs.GetGeneral())
	return ""
}

func Decode() {
	fmt.Println(configs.GetGeneral())
}

func Sign() {
	fmt.Println(configs.GetGeneral())
}

func Verify() {
	fmt.Println(configs.GetGeneral())
}
