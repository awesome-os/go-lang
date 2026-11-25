package main

import (
	"fmt"
	"os"
	"path/filepath"

	casv11 "github.com/awesome-os/go-lang/b8g-casv11"
)

func main() {
	root := os.Getenv("AWESOME_OS_CAS_ROOT")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "b8g-gocacheprog: %v\n", err)
			os.Exit(1)
		}
		root = filepath.Join(home, ".b8g", "cas")
	}
	store := casv11.NewStore(root)
	if err := casv11.ServeGocacheProg(store, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "b8g-gocacheprog: %v\n", err)
		os.Exit(1)
	}
}
