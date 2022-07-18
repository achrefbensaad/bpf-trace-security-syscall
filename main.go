package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

type execve_events struct {
	Pid     uint32
	Ret     uint32
	Syscall uint32

	Path [255]byte
	Comm [16]byte
}

func LoadTracing(syscalls []string, m *bpf.Module) error {
	println("Loading BPF programs")
	for _, syscall := range syscalls {
		prog, err := m.LoadKprobe(fmt.Sprintf("trace_%s", syscall))
		if err != nil {
			fmt.Printf("Failed to load function %s", fmt.Sprintf("trace_%s\n", syscall))
			return err
		}
		progret, err := m.LoadKprobe(fmt.Sprintf("traceret_%s", syscall))
		if err != nil {
			fmt.Printf("Failed to load function %s", fmt.Sprintf("traceret_%s\n", syscall))
			return err
		}

		err = m.AttachKprobe(syscall, prog, -1)
		if err != nil {
			fmt.Printf("Failed to attach function %s to syscall %s\n", fmt.Sprintf("traceret_%s", syscall), syscall)
			return err
		}
		err = m.AttachKretprobe(syscall, progret, -1)
		if err != nil {
			fmt.Printf("Failed to attach function %s to syscall %s\n", fmt.Sprintf("traceret_%s", syscall), syscall)
			return err
		}
		fmt.Printf("Tracing syscall %s\n", syscall)
	}
	println("All BPF programs were loaded")
	return nil
}

func main() {
	bpfsourcefile := "./bpf/hello.c"

	content, err := ioutil.ReadFile(bpfsourcefile)
	if err != nil {
		panic(err)
	}
	bpfsource := string(content)
	println("Creating BPF program")
	m := bpf.NewModule(bpfsource, []string{})
	defer m.Close()
	syscallArray := []string{"security_path_unlink", "security_path_rmdir", "security_path_mkdir", "security_path_mknod", "security_path_symlink"}
	LoadTracing(syscallArray, m)
	table := bpf.NewTable(m.TableId("events"), m)
	c := make(chan []byte, 1000)

	perfMap, err := bpf.InitPerfMap(table, c, nil)
	if err != nil {
		fmt.Printf("Failed to init perf map %s\n", err)
		os.Exit(1)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	go func() {
		fmt.Println("***********")
		PrintHeader()
		path := make(map[uint32][]string)
		for {
			data := <-c
			var event execve_events
			err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)

			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			if event.Ret == 0 {
				fullpatharray := path[event.Pid]
				com := C.GoString((*C.char)(unsafe.Pointer(&event.Comm)))
				fullpath := strings.Join(fullpatharray, "/")
				if len(fullpath) > 0 {
					fullpath = fullpath[1:]
				}
				PrintLine(com, event.Syscall, event.Pid, fullpath)
				delete(path, event.Pid)
				continue
			}
			elem := C.GoString((*C.char)(unsafe.Pointer(&event.Path)))
			e, ok := path[event.Pid]
			if !ok {
				e = make([]string, 0)
			}
			e = append([]string{elem}, e...)
			path[event.Pid] = e
		}
	}()
	perfMap.Start()
	<-sig
	perfMap.Stop()
}

func PrintHeader() {
	fmt.Printf("%-16s|%-16s|%-10s|%-s\n", "Command", "Syscall", "Pid", "Target")
}

func PrintLine(command string, syscall uint32, pid uint32, target string) {
	var syscallname string
	switch syscall {
	case 0:
		syscallname = "unlink"
	case 1:
		syscallname = "rmdir"
	case 2:
		syscallname = "mkdir"
	case 3:
		syscallname = "mknod"
	case 4:
		syscallname = "symlink"
	default:
		syscallname = "unknown"
	}
	fmt.Printf("%-16s|%-16s|%-10d|%-s\n", command, syscallname, pid, target)
}
