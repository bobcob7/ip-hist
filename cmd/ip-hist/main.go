package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/bobcob7/ip-hist/pkg/counter"
	"github.com/mum4k/termdash"
	"github.com/mum4k/termdash/cell"
	"github.com/mum4k/termdash/container"
	"github.com/mum4k/termdash/container/grid"
	"github.com/mum4k/termdash/linestyle"
	"github.com/mum4k/termdash/terminal/termbox"
	"github.com/mum4k/termdash/terminal/terminalapi"
	"github.com/mum4k/termdash/widgets/linechart"
	"github.com/mum4k/termdash/widgets/text"
	"golang.org/x/net/context"
)

var maxSeriesLen int
var pinnedFile string
var refreshRate time.Duration

var interfaceColors = []cell.Color{
	cell.Color(2),  // Red
	cell.Color(3),  // Lime
	cell.Color(4),  // Yellow
	cell.Color(5),  // Blue
	cell.Color(6),  // Fuchsia
	cell.Color(7),  // Aqua
	cell.Color(10), // Red
	cell.Color(11), // Lime
	cell.Color(12), // Yellow
	cell.Color(13), // Blue
	cell.Color(14), // Fuchsia
	cell.Color(15), // Aqua
}

func init() {
	flag.IntVar(&maxSeriesLen, "max-series", 60, "Max number of records that are displayed on the graph")
	flag.StringVar(&pinnedFile, "pinned-file", "/sys/fs/bpf/tc/globals/packet_count", "Path to the pinned BPF map, this is usually somewhere in /sys/fs/bpf")
	flag.DurationVar(&refreshRate, "refresh", time.Second, "Time between polling the BPF map")
}

func main() {
	flag.Parse()
	ctx, done := context.WithCancel(context.Background())
	defer done()
	count, err := counter.NewPacketCounter(pinnedFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to initial packet counter:", err)
	}
	data := count.Run(ctx, refreshRate)

	// Create the terminal.
	t, err := termbox.New()
	if err != nil {
		panic(err)
	}
	defer t.Close()

	// Create a widget.
	packetGraph, err := linechart.New(
		linechart.YAxisFormattedValues(linechart.ValueFormatterRound),
	)
	if err != nil {
		panic(err)
	}
	legend, _ := text.New()
	builder := grid.New()
	builder.Add(grid.ColWidthPerc(90, grid.Widget(packetGraph,
		container.Border(linestyle.Light), container.BorderTitle("C=Clear Q=Quit"))))
	builder.Add(grid.ColWidthFixed(42, grid.Widget(legend,
		container.Border(linestyle.Light))))
	// builder.Add(grid.Widget(packetGraph)))
	gridWidget, err := builder.Build()

	if err != nil {
		panic(err)
	}

	// Create the container with a widget.
	c, err := container.New(t, gridWidget...)
	if err != nil {
		panic(err)
	}

	series := make(map[int][]float64, runtime.NumCPU())

	// Create the controller and disable periodic redraw.
	ctrl, err := termdash.NewController(t, c, termdash.KeyboardSubscriber(func(k *terminalapi.Keyboard) {
		if k.Key == 'q' || k.Key == 'Q' {
			done()
		}
		if k.Key == 'c' || k.Key == 'C' {
			series = make(map[int][]float64, runtime.NumCPU())
		}
	}))
	if err != nil {
		panic(err)
	}
	defer ctrl.Close()

	// Subscribe to signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sig:
			done()
		case values, ok := <-data:
			if !ok {
				return
			}
			legend.Reset()
			for cpu, value := range values {
				// Add to series
				if _, ok := series[cpu]; !ok {
					series[cpu] = make([]float64, 0)
				}
				if len(series[cpu]) > maxSeriesLen {
					series[cpu] = series[cpu][1:]
				}
				series[cpu] = append(series[cpu], float64(value))
				if len(interfaceColors) >= cpu {
					// Generate random color
					interfaceColors = append(interfaceColors, cell.Color((rand.Int()%(256+16))+16))
				}
				packetGraph.Series(
					fmt.Sprintf("CPU #%d", cpu),
					series[cpu],
					linechart.SeriesCellOpts(cell.FgColor(interfaceColors[cpu])),
				)
				legend.Write(fmt.Sprintf("CPU#%d:%d\n", cpu, value), text.WriteCellOpts(cell.FgColor(interfaceColors[cpu])))
			}

			// Redraw the terminal manually.
			if err := ctrl.Redraw(); err != nil {
				panic(err)
			}
		}
	}
}
