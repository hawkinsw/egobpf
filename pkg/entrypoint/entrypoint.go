package entrypoint

import (
	"fmt"
	"unsafe"
)

type Entrypoint struct {
	entrypoint unsafe.Pointer
}

func NewEntrypoint(ep unsafe.Pointer) *Entrypoint {
	return &Entrypoint{ep}
}
func (e *Entrypoint) Repr() string {
	return fmt.Sprintf("0x%x", e.entrypoint)
}
func (e *Entrypoint) Addr() uintptr {
	return uintptr(e.entrypoint)
}

func (e *Entrypoint) Preamble(preamble_length uint32) []byte {
	result := make([]byte, 0)
	for op_idx := 0; op_idx < int(preamble_length); op_idx++ {
		result = append(result, *(*byte)(unsafe.Pointer(((uintptr)(e.entrypoint) + uintptr(op_idx)))))
	}
	return result
}
