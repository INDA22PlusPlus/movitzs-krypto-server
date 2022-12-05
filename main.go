package main

import (
	"fmt"
	"os"
)

func main() {
	err := realMain()
	if err != nil {
		fmt.Printf("main err: " + err.Error())
		os.Exit(1)
	}
}

func realMain() error {
	return nil
}
