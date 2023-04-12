package hookable

import (
	"fmt"
	"io"
	"math"
	"reflect"
	"unsafe"

	"github.com/hawkinsw/egobpf/v2/internal/utilities"
	"github.com/hawkinsw/egobpf/v2/pkg/entrypoint"
	"github.com/hawkinsw/egobpf/v2/pkg/platform"
	"golang.org/x/sys/unix"
)

func Testing() {
	fmt.Printf("Well, I can't believe that this actually works\n")
}

type Hookable struct {
	name        string
	entrypoint  *entrypoint.Entrypoint
	rfenterCall unsafe.Pointer
	rfexitCalls []unsafe.Pointer
	length      int // Make this an optional type -- for now, all Hookables must have length >= 0
}

func NewHookable(name string, entrypoint *entrypoint.Entrypoint, rfenterCall unsafe.Pointer, rfexitCalls []unsafe.Pointer, length int) Hookable {
	return Hookable{name, entrypoint, rfenterCall, rfexitCalls, length}
}

func (h *Hookable) String() string {
	return h.name
}

func (h *Hookable) Entrypoint() *entrypoint.Entrypoint {
	return h.entrypoint
}

func (h *Hookable) Name() string {
	return h.name
}

func (h *Hookable) Repr() string {
	return fmt.Sprintf("%v at %v (size: 0x%x)", h.name, h.entrypoint.Repr(), h.length)
}

func (h *Hookable) Write(writer io.Writer) {
	repr := h.Repr()
	writer.Write([]byte(repr))
}

func (h *Hookable) RaceFuncEnter() unsafe.Pointer {
	return h.rfenterCall
}

func (h *Hookable) RaceFuncExits() []unsafe.Pointer {
	return h.rfexitCalls
}
func (h *Hookable) HookTo(ht interface{}) error {

	hookTarget := reflect.ValueOf(ht)
	if hookTarget.Kind() != reflect.Func {
		return fmt.Errorf("cannot hook to a non-Func target")
	}
	hookTargetAddr := (uintptr)(hookTarget.Pointer())
	ripAddr := (uintptr(h.rfenterCall) + platform.CallInsnSize)
	callDelta := int64(hookTargetAddr - ripAddr)

	if callDelta > math.MaxInt32 || callDelta < math.MinInt32 {
		return fmt.Errorf("target function too far away")
	}

	callInsn := make([]byte, platform.CallInsnSize)
	callInsn[0] = 0xe8
	copy(callInsn[1:], utilities.Int32AsLeBytes(int32(callDelta)))

	platform.SetContainingPagePermissions(h.rfenterCall, unix.PROT_READ|unix.PROT_EXEC|unix.PROT_WRITE)
	platform.RewriteCall(uintptr(h.rfenterCall), callInsn)
	platform.SetContainingPagePermissions(h.rfenterCall, unix.PROT_READ|unix.PROT_EXEC)
	return nil
}

type Hookables struct {
	elements []Hookable
}

func (hs *Hookables) Len() int {
	return len(hs.elements)
}

func (hs *Hookables) Swap(i, j int) {
	temp := hs.elements[i]
	hs.elements[i] = hs.elements[j]
	hs.elements[j] = temp
}

func (hs *Hookables) Less(i, j int) bool {
	return hs.elements[i].entrypoint.Addr() < hs.elements[j].entrypoint.Addr()
}

func (hs *Hookables) Add(hookable Hookable) {
	hs.elements = append(hs.elements, hookable)
}

func (hs *Hookables) Rangeable() []*Hookable {
	var result []*Hookable
	for idx := range hs.elements {
		result = append(result, &hs.elements[idx])
	}
	return result
}

func (hs *Hookables) At(idx int) *Hookable {
	return &hs.elements[idx]
}

func (hs *Hookables) Write(writer io.Writer) {
	for _, hookable := range hs.elements {
		hookable.Write(writer)
	}
}

func (hs *Hookables) Find(name string) (*Hookable, error) {
	for _, hookable := range hs.elements {
		if hookable.name == name {
			return &hookable, nil
		}
	}
	return nil, fmt.Errorf("could not find %v", name)
}
