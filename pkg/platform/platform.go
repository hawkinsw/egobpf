package platform

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const CallInsnSize = 5

func SetContainingPagePermissions(addr unsafe.Pointer, perms int) bool {
	page := uintptr(addr) & ^(uintptr(os.Getpagesize()) - 1)
	pageSlice := unsafe.Slice((*byte)(unsafe.Pointer(page)), os.Getpagesize())
	unix.Mprotect(pageSlice, perms)
	return true
}

func RewriteCall(callAddr uintptr, insn []byte) bool {

	fmt.Printf("Attempting to write: ")
	for _, b := range insn {
		fmt.Printf("%x ", b)
	}
	fmt.Printf("\n")

	targetByte := (*byte)(unsafe.Pointer((uintptr)(callAddr) + 0))
	*targetByte = insn[0]
	targetByte = (*byte)(unsafe.Pointer((uintptr)(callAddr) + 1))
	*targetByte = insn[1]
	targetByte = (*byte)(unsafe.Pointer((uintptr)(callAddr) + 2))
	*targetByte = insn[2]
	targetByte = (*byte)(unsafe.Pointer((uintptr)(callAddr) + 3))
	*targetByte = insn[3]
	targetByte = (*byte)(unsafe.Pointer((uintptr)(callAddr) + 4))
	*targetByte = insn[4]

	return true
}
