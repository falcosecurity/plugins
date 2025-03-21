//go:build exe

package main

/*
#include <stdio.h>
#include <stdbool.h>
void echo_cb(const char *json, bool added) {
	printf("Added: %d, Json: %s\n", added, json);
}
*/
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	initCfg := `
   {
      "label_max_len": 100,
      "with_size": true,
      "engines": {
		  "containerd":{
			 "enabled":true,
			 "sockets":[
				"/run/containerd/containerd.sock",
				"/run/k3s/containerd/containerd.sock"
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
	ptr := StartWorker((*[0]byte)(C.echo_cb), cstr)
	if ptr == nil {
		fmt.Println("Failed to start worker; nothing configured?")
		os.Exit(1)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Blocking, press ctrl+c to continue...")
	<-done

	fmt.Println("Stopping worker")
	StopWorker(ptr)
}
