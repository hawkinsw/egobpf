package main

import (
	"fmt"

	"github.com/hawkinsw/egobpf/v2/pkg/egobpf"
)

func hook_test() {
	fmt.Printf("hook worked.\n")
}

//go:noinline
func test() {
	fmt.Printf("I am being tested.\n")
}

func main() {
	hookables, err := egobpf.Initialize()

	if err != nil {
		fmt.Printf("Oops: %v\n", err)
		return
	}

	test()
	if testHookable, err := hookables.Find("main.test"); err != nil {
		fmt.Printf("Oops: %v\n", err)
		return
	} else {
		testHookable.HookTo(hook_test)
		test()
	}

}
