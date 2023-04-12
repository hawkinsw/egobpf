package loader

import (
	"io"

	"github.com/cilium/ebpf"
)

func LoadFromReaderAt(reader io.ReaderAt) (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(reader)
}
