package store

import "github.com/anacrolix/torrent/metainfo"

type Target = metainfo.Hash

type Store interface {
	Put(*Item) error
	Get(Target) (*Item, error)
}
