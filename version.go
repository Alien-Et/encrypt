package main

import (
	"fmt"
	"os"
)

// Version is the current version of the encrypt tool
const Version = "v1.0.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v", "--version":
			fmt.Printf("encrypt tool %s\n", Version)
		default:
			fmt.Printf("Usage: %s [-v|--version]\n", os.Args[0])
		}
	} else {
		fmt.Printf("%s\n", Version)
	}
}