package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"context"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 counter counter.c

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	keys := map[string]uint32{
		"Read":  0,
		"Write": 1,
		"Open":  2,
	}
	
	counts := make(map[string]uint64)
	
	
	log.Printf("Read syscall has been called %d times in the past 5 seconds", counts["Read"])
	log.Printf("Write syscall has been called %d times in the past 5 seconds", counts["Write"])
	log.Printf("Open syscall has been called %d times in the past 5 seconds", counts["Open"])

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Print("Error loading eBPF objects:", err)
	}

	defer objs.Close()

	_, err := link.Tracepoint("syscalls", "sys_enter_read", objs.counterPrograms.CountReadCalls, nil)
	if err != nil {
		log.Fatalf("opening tracepoint for read: %s", err)
	}

	_, err = link.Tracepoint("syscalls", "sys_enter_open", objs.counterPrograms.CountOpenCalls, nil)
	if err != nil {
		log.Fatalf("opening tracepoint for open: %s", err)
	}
	_, err = link.Tracepoint("syscalls", "sys_enter_write", objs.counterPrograms.CountWriteCalls, nil)
	if err != nil {
		log.Fatalf("opening tracepoint for write: %s", err)
	}

	readCounterMap := objs.counterMaps.SyscallCountMap
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("closing counter eBPF program")
			return
		case <-ticker.C:
			for name, key := range keys {
				var value uint64
				if err := readCounterMap.Lookup(key, &value); err == nil {
					counts[name] = value
				} else {
					log.Println("map lookup failed", err)
					counts[name] = 0
				}

				logMessage := "Syscall counts in the past 5 seconds:\n" +
				fmt.Sprintf(" - Read: %d times\n", counts["Read"]) +
				fmt.Sprintf(" - Write: %d times\n", counts["Write"]) +
				fmt.Sprintf(" - Open: %d times\n", counts["Open"])
				log.Println(logMessage)
			}
		}
	}
}
