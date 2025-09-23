//go:build exe

package main

/*
#include <stdio.h>
#include <stdbool.h>
void echo_cb(const char *json, bool added, bool initial_state) {
	if (initial_state) {
		printf("[Pre-existing] Json: %s\n", json);
	} else {
		printf("[%s] Json: %s\n", added ? "Added" : "Removed", json);
	}
}
*/
import "C"

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Enable pprof
	go func() {
		fmt.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	initCfg := `
   {
      "label_max_len": 100,
      "with_size": true,
      "engines": {
		  "containerd":{
			 "enabled":true,
			 "sockets":[
				"/run/containerd/containerd.sock",
				"/run/k3s/containerd/containerd.sock",
				"/var/snap/microk8s/common/run/containerd.sock"
			 ]
		  },
		  "cri":{
			 "enabled":true,
			 "sockets":[
				"/run/crio/crio.sock"
			 ]
		  },
		  "docker":{
			 "enabled":true,
			 "sockets":[
				"/var/run/docker.sock"
			 ]
		  },
		  "podman":{
			 "enabled":true,
			 "sockets":[
				"/run/podman/podman.sock",
				"/run/user/1000/podman/podman.sock"
			 ]
		  }
      }
   }`
	if len(os.Args) > 1 {
		initCfg = os.Args[1]
	}
	fmt.Println("Starting worker")
	cstr := C.CString(initCfg)
	enabledSocks := C.CString("")
	ptr := StartWorker((*[0]byte)(C.echo_cb), cstr, &enabledSocks)
	if ptr == nil {
		fmt.Println("Failed to start worker; nothing configured?")
		os.Exit(1)
	}
	socks := C.GoString(enabledSocks)
	fmt.Println("Started worker with attached socks:", socks)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Blocking, press ctrl+c to continue...")
	<-done

	fmt.Println("Stopping worker")
	StopWorker(ptr)
}
