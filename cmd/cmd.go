package main

import (
	"flag"
	"fmt"
	"os"

	egobpf_elf "github.com/hawkinsw/egobpf/v2/internal"
)

var (
	binaryPath = flag.String("binaryPath", "a.out", "Path to the file from which methods are to be gathered.")
)

func main() {
	flag.Parse()

	_, err := egobpf_elf.NewElfGoProgram(*binaryPath)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open the binary file: %v\n", err)
		return
	}

	fmt.Printf("Successfully opened the binary file!\n")

}
