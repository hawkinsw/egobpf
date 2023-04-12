package introspect

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"sort"
	"unsafe"

	"github.com/hawkinsw/egobpf/v2/internal/utilities"
	"github.com/hawkinsw/egobpf/v2/pkg/entrypoint"
	"github.com/hawkinsw/egobpf/v2/pkg/hookable"
	"github.com/hawkinsw/egobpf/v2/pkg/platform"
	"golang.org/x/sys/unix"
)

// The next several types must be kept in sync with their definitions
// from the runtime.
type name struct {
	bytes *byte
}

type nameOff int32
type typeOff int32
type tflag uint8
type functab struct {
	entryOff uint32
	funcOff  uint32
}

type moduledata struct {
	_ struct{ _ struct{} }

	_           *byte
	funcnametab []byte
	_           []uint32
	_           []byte
	_           []byte
	pclntable   []byte
	ftab        []functab
}

type funcInfo struct {
	_ struct{ _ struct{} }

	_       uint32
	nameOff int32 // Index into moduledata.funcnametab
}

//go:linkname racefuncenter_detector runtime.racefuncenter
func racefuncenter_detector(uintptr)

//go:linkname racefuncexit_detector runtime.racefuncexit
func racefuncexit_detector(uintptr)

//go:linkname typeLinks reflect.typelinks
func typeLinks() (sections []unsafe.Pointer, offset [][]int32)

//go:linkname resolveNameOff runtime.resolveNameOff
func resolveNameOff(unsafe.Pointer, int32) unsafe.Pointer

//go:linkname activeModules runtime.activeModules
func activeModules() []*moduledata

//go:linkname findNull runtime.findnull
func findNull(s *byte) int

//go:linkname textAddr runtime.(*moduledata).textAddr
func textAddr(*moduledata, uint32) int

//go:linkname readVarint runtime.(*name).readVarint
func readVarint(name, int) (int, int)

func (n name) data(off int) *byte {
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(n.bytes)) + uintptr(off)))

}

const nop byte = 0x90

// readVarint parses a varint as encoded by encoding/binary.
// It returns the number of encoded bytes and the encoded value.S
/*
func (n name) readVarint(off int) (int, int) {
	v := 0
	for i := 0; ; i++ {
		x := *n.data(off + i)
		v += int(x&0x7f) << (7 * i)
		if x&0x80 == 0 {
			return i + 1, v
		}
	}
}
*/
func FindRaceFuncExitCalls(entrypoint entrypoint.Entrypoint, length int) ([]unsafe.Pointer, error) {
	racefuncexitAddr := (uintptr)(reflect.ValueOf(racefuncexit_detector).Pointer())

	racefuncexitptrs := make([]unsafe.Pointer, 0)

	for i := 0; i < length-5; i++ {
		insnAddr := entrypoint.Addr() + uintptr(i)
		insnPtr := unsafe.Pointer(insnAddr)

		offsetToRaceFuncExit := racefuncexitAddr - (insnAddr + 5)
		sequence := make([]byte, 5)
		sequence[0] = 0xe8
		copy(sequence[1:], utilities.Int32AsLeBytes(int32(offsetToRaceFuncExit)))

		if bytes.Equal(sequence, (unsafe.Slice((*byte)(insnPtr), 5))) {
			fmt.Printf("Found a racefuncexit call at 0x%x\n", insnAddr)
			racefuncexitptrs = append(racefuncexitptrs, insnPtr)
		}
	}
	if len(racefuncexitptrs) == 0 {
		return nil, fmt.Errorf("could not find the race detector call")
	}
	return racefuncexitptrs, nil
}

func FindRaceFuncEnterCall(entrypoint entrypoint.Entrypoint, length int) (unsafe.Pointer, error) {
	racefuncenterAddr := (uintptr)(reflect.ValueOf(racefuncenter_detector).Pointer())

	for i := 0; i < length-5; i++ {
		insnAddr := entrypoint.Addr() + uintptr(i)
		insnPtr := unsafe.Pointer(insnAddr)

		offsetToRaceFuncEnter := racefuncenterAddr - (insnAddr + 5)
		sequence := make([]byte, 5)
		sequence[0] = 0xe8
		copy(sequence[1:], utilities.Int32AsLeBytes(int32(offsetToRaceFuncEnter)))

		if bytes.Equal(sequence, (unsafe.Slice((*byte)(insnPtr), 5))) {
			fmt.Printf("Found a racefuncenter call at 0x%x\n", insnAddr)
			return insnPtr, nil
		}
	}
	return nil, fmt.Errorf("could not find the race detector call")
}

func FindHookableFunctions() (hookable.Hookables, error) {
	var internalHookables hookable.Hookables
	var resultHookables hookable.Hookables

	modules := activeModules()
	for _, module := range modules {
		for fc := 0; fc < len(module.ftab); fc++ {
			funcPc := textAddr(module, module.ftab[fc].entryOff)
			funcInfoOff := module.ftab[fc].funcOff

			funcInformation := (*funcInfo)(unsafe.Pointer(&module.pclntable[funcInfoOff]))

			funcNameStart := (*byte)(unsafe.Pointer(&module.funcnametab[funcInformation.nameOff]))
			funcNameLen := findNull(funcNameStart)

			funcNameSlice := make([]byte, funcNameLen)
			for i := 0; i < funcNameLen; i++ {
				funcNameSlice[i] = *(*byte)((unsafe.Pointer((uintptr)(unsafe.Pointer(funcNameStart)) + (uintptr)(i))))
			}
			funcName := (string)(funcNameSlice)
			entryPointPointer := unsafe.Pointer(uintptr(funcPc))
			internalHookables.Add(hookable.NewHookable(funcName, entrypoint.NewEntrypoint(entryPointPointer), unsafe.Pointer(uintptr(0)), make([]unsafe.Pointer, 0), -1))
		}
	}

	sort.Sort(&internalHookables)

	// Now, we have all the hookables and they are in order. Let's walk through them all and use the entry point
	// of the one that follows in order to determine where each ends.
	for idx, internal_hookable := range internalHookables.Rangeable() {
		if idx+1 < internalHookables.Len() {
			hookableLength := (int)(internalHookables.At(idx+1).Entrypoint().Addr() - internal_hookable.Entrypoint().Addr())
			if raceFuncEnterCall, err := FindRaceFuncEnterCall(*internal_hookable.Entrypoint(), hookableLength); err != nil {
				continue
			} else if raceFuncExitCalls, err := FindRaceFuncExitCalls(*internal_hookable.Entrypoint(), hookableLength); err != nil {
				continue
			} else {
				resultHookables.Add(hookable.NewHookable(internal_hookable.Name(), internal_hookable.Entrypoint(), raceFuncEnterCall, raceFuncExitCalls, hookableLength))
			}
		}
	}

	return resultHookables, nil
}

func NullifyHookable(h *hookable.Hookable) error {

	// 0. Make the page that holds these bytes readable/writable/executable (temporarily)
	targetPage := uintptr(h.RaceFuncEnter()) & ^(uintptr(os.Getpagesize()) - 1)
	targetPageSlice := unsafe.Slice((*byte)(unsafe.Pointer(targetPage)), os.Getpagesize())
	unix.Mprotect(targetPageSlice, unix.PROT_WRITE|unix.PROT_READ|unix.PROT_EXEC)

	target := (*uint64)(unsafe.Pointer(uintptr(h.RaceFuncEnter())))
	old := *target
	//new := (uint64)((uintptr(old) & 0xffffff0000000000) | 0x000000c031489090)
	new := (uint64)((uintptr(old) & 0xffffff0000000000) | 0x0000009090909090)
	*target = new
	unix.Mprotect(targetPageSlice, unix.PROT_READ|unix.PROT_EXEC)

	for _, exit := range h.RaceFuncExits() {
		targetPage := uintptr(exit) & ^(uintptr(os.Getpagesize()) - 1)
		targetPageSlice := unsafe.Slice((*byte)(unsafe.Pointer(targetPage)), os.Getpagesize())
		unix.Mprotect(targetPageSlice, unix.PROT_WRITE|unix.PROT_READ|unix.PROT_EXEC)

		sequence := []byte{0x90, 0x90, 0x90, 0x90, 0x90}
		platform.RewriteCall(uintptr(exit), sequence)

		fmt.Printf("target: 0x%x targetPage: 0x%x\n", target, targetPage)
		unix.Mprotect(targetPageSlice, unix.PROT_READ|unix.PROT_EXEC)
	}

	// n. Make the page that holds these bytes readable/executable
	unix.Mprotect(targetPageSlice, unix.PROT_READ|unix.PROT_EXEC)
	return nil
}
