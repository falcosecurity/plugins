package config

import (
	"encoding/json"
)

const (
	HookCreate = 1 << iota
	HookStart
	HookRemove

	defaultLabelMaxLen = 100
)

type SocketsEngine struct {
	Enabled bool     `json:"enabled"`
	Sockets []string `json:"sockets"`
}

type EngineCfg struct {
	SocketsEngines map[string]SocketsEngine `json:"engines"`
	LabelMaxLen    int                      `json:"label_max_len"`
	WithSize       bool                     `json:"with_size"`
	HostRoot       string                   `json:"host_root"`
	Hooks          byte                     `json:"hooks"`
}

var c EngineCfg

// Init sets cfg default values
func init() {
	c.LabelMaxLen = defaultLabelMaxLen
	c.WithSize = false
	// We will always override it when called by C++ plugin.
	// By default, for go-worker executable (make exe) and go-worker tests,
	// we attach remove hook too.
	c.Hooks = HookCreate | HookRemove
}

func Load(initCfg string) error {
	err := json.Unmarshal([]byte(initCfg), &c)
	if err != nil {
		return err
	}
	return nil
}

func Get() EngineCfg {
	return c
}

func GetLabelMaxLen() int {
	return c.LabelMaxLen
}

func GetWithSize() bool {
	return c.WithSize
}

func GetHostRoot() string {
	return c.HostRoot
}

func IsHookEnabled(hook byte) bool {
	return c.Hooks&hook != 0
}
