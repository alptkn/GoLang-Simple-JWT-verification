package main

import (
	"fmt"
	"jwt-example/configs"
	"jwt-example/handler"
	"net/http"
)

func main() {
	configs.LoadConfigs()
	http.HandleFunc("/wellcome", handler.WellCome)
	http.HandleFunc("/signin", handler.SignIn)
	http.HandleFunc("/refresh", handler.RefreshToken)
	fmt.Println(fmt.Sprintf("Server started at port %s", configs.Configs.LocalServerPort))
	err := http.ListenAndServe(configs.Configs.LocalServerPort, nil)
	if err != nil {
		panic(err)
	}

}
