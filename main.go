package main

import (
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

	readCounterMap := objs.counterMaps.SyscallCountMap
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("closing counter eBPF program")
			return
		case <-ticker.C:
			key := uint32(0)
			var value uint32
			readCounterMap.Lookup(key, &value)
			log.Printf("Read syscall has been called %d times in the past 5 seconds", value)
		}
	}
}
