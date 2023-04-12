package loader_test

import (
	"os"
	"testing"

	"github.com/hawkinsw/egobpf/v2/pkg/loader"
)

func TestSimpleLoad(t *testing.T) {
	rat, err := os.Open("../../ebpf-tests/simple.bpf.o")
	if err != nil {
		t.Fatalf("Could not open simple.bpf.o: %v", err)
	}
	cs, err := loader.LoadFromReaderAt(rat)
	if err != nil {
		t.Fatalf("Could not load simple.bpf.o: %v", err)
	}

	main__test := cs.Programs["main__test"]

	if main__test == nil {
		t.Fatalf("simple.bpf.o did not contain main__test")
	}
	if main__test.SectionName != "main.test" {
		t.Fatalf("main__test was not in main.test section.")
	}
	rat.Close()
}
