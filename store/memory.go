package store

import (
	"sync"

	"github.com/anacrolix/torrent/metainfo"
)

var _ Store = &Memory{}

type Memory struct {

	// Protects m
	mu sync.RWMutex
	m  map[Target]*Item
}

func NewMemory() *Memory {
	return &Memory{
		m: make(map[metainfo.Hash]*Item),
	}
}

func (m *Memory) Put(i *Item) error {
	if err := i.Check(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.m[i.Target]
	if !ok {
		m.m[i.Target] = i
		return nil
	}

	if i.Seq <= old.Seq {
		return ErrSeqField
	}

	return nil
}

func (m *Memory) Get(t Target) (*Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.m[t], nil
}
