package main

import "fmt"

func debugln(args ...interface{}) {
	fmt.Println(args...)
}

func debugf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}
