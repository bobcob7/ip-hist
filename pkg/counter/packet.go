package counter

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/bobcob7/ip-hist/pkg/bpf"
)

type PacketCounter struct {
	fd     int
	values []uint64
}

func NewPacketCounter(PinnedFilePath string) (PacketCounter, error) {
	fd, err := bpf.ObjGet(PinnedFilePath)
	if err != nil {
		return PacketCounter{}, fmt.Errorf("failed to open map %w", err)
	}
	return PacketCounter{
		fd:     fd,
		values: make([]uint64, runtime.NumCPU()),
	}, nil
}

func (p PacketCounter) Run(ctx context.Context, d time.Duration) <-chan []uint64 {
	output := make(chan []uint64)
	key := 0
	go func() {
		defer close(output)
		var err error
		t := time.NewTicker(d)
		for {
			select {
			case <-t.C:
				err = bpf.LookupElement(p.fd, &key, p.values)
				if err != nil {
					return
				}
				currentValues := make([]uint64, runtime.NumCPU())
				copy(currentValues, p.values)
				output <- currentValues
			case <-ctx.Done():
				return
			}
		}
	}()
	return output
}
