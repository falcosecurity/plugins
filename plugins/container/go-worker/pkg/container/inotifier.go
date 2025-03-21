package container

import (
	"context"
	"github.com/fsnotify/fsnotify"
	"os"
	"path/filepath"
	"strings"
)

type EngineInotifier struct {
	watcher           *fsnotify.Watcher
	watcherGenerators map[string]EngineGenerator
}

func (e *EngineInotifier) Listen() <-chan fsnotify.Event {
	if e.watcher == nil {
		return nil
	}
	return e.watcher.Events
}

func (e *EngineInotifier) Process(ctx context.Context, val interface{}) Engine {
	ev, _ := val.(fsnotify.Event)
	if cb, ok := e.watcherGenerators[ev.Name]; ok {
		_ = e.watcher.Remove(filepath.Dir(ev.Name))
		engine, _ := cb(ctx)
		return engine
	} else {
		// If the new created path is a folder, check if
		// it is a subpath of any watcherGenerator socket,
		// and eventually add a new watch, removing the old one
		fileInfo, err := os.Stat(ev.Name)
		if err != nil || !fileInfo.IsDir() {
			return nil
		}
		for socket, cb := range e.watcherGenerators {
			if strings.HasPrefix(socket, ev.Name) {
				// Remove old watch
				_ = e.watcher.Remove(filepath.Dir(ev.Name))
				// It may happen that the actual socket has already been created.
				// Check it and if it is not created yet, add a new inotify watcher.
				if _, statErr := os.Stat(socket); os.IsNotExist(statErr) {
					// Add new watch
					_ = e.watcher.Add(ev.Name)
					break
				} else {
					engine, _ := cb(ctx)
					return engine
				}
			}
		}
	}
	return nil
}

func (e *EngineInotifier) Close() {
	if e.watcher == nil {
		return
	}
	_ = e.watcher.Close()
}
