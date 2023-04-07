package egobpf_elf

import (
	"io"
	"os"
)

type ElfGoProgram struct {
	filename string
	file     io.Reader
}

func NewElfGoProgram(filename string) (*ElfGoProgram, error) {
	osFile, err := os.OpenFile(filename, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	return &ElfGoProgram{filename, osFile}, nil
}
