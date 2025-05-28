package main

import (
	"agent-auth/internal/auth"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run gen_token.go <agentID>")
		os.Exit(1)
	}
	agentID := os.Args[1]
	privPath := fmt.Sprintf("configs/keys/%s-%s.key", agentID[:5], agentID[5:])
	privKey, err := os.ReadFile(privPath)
	if err != nil {
		panic(err)
	}
	token, err := auth.CreateToken(agentID, privKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(token)
}
