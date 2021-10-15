package store

import (
	"crypto/ed25519"
	"crypto/sha1"
	"errors"
	"fmt"

	"github.com/anacrolix/torrent/bencode"
)

var ErrBadItem = errors.New("bad item")
var ErrVFieldTooBig = errors.New("message (v field) too big")
var ErrSeqField = errors.New("modified item has a lower or equal seq value")

type Item struct {
	// Target MUST be the SHA-1 hash of K concatenated with Salt, if present, on mutable items
	Target [20]byte
	// Value to be stored bencoded
	V []byte

	// 32 byte ed25519 public key
	K [32]byte
	// used if present to generate Target
	Salt []byte
	Sig  [64]byte
	Cas  []byte
	Seq  uint64
}

func NewItem(value []byte) (*Item, error) {
	v, err := bencode.Marshal(value)
	if err != nil {
		return nil, err
	}

	return &Item{
		V:      value,
		Target: sha1.Sum(v),
	}, nil
}

func NewMutableItem(value, salt, cas []byte, seq uint64, k ed25519.PrivateKey) (*Item, error) {
	v, err := bencode.Marshal(value)
	if err != nil {
		return nil, err
	}

	pk := []byte(k.Public().(ed25519.PublicKey))
	var kk [32]byte
	copy(kk[:], pk)

	var sig [64]byte
	copy(sig[:], ed25519.Sign(k, bufferToSign(salt, v, seq)))

	return &Item{
		V:    v,
		Salt: salt,
		Cas:  cas,
		Seq:  seq,

		K:      kk,
		Target: sha1.Sum(append(kk[:], salt...)),
		Sig:    sig,
	}, nil
}

func bufferToSign(salt, bv []byte, seq uint64) []byte {
	var bts []byte
	if salt != nil {
		bts = append(bts, []byte("4:salt")...)
		x := bencode.MustMarshal(salt)
		bts = append(bts, x...)
	}
	bts = append(bts, []byte(fmt.Sprintf("3:seqi%de1:v", seq))...)
	bts = append(bts, bv...)
	return bts
}

// Calc calculates the target and the signature of a Storage Item.
// If a private key is provided, the item will be writable using this key.
// If no key is provided, the item will be read only.
func (s *Item) Calc(k ed25519.PrivateKey, vlen int) error {
	v, err := bencode.Marshal(s.V)
	if err != nil {
		return err
	}

	if len(v) > vlen {
		return ErrVFieldTooBig
	}

	if k == nil {
		s.Target = sha1.Sum(v)
		return nil
	}

	pk := k.Public().(ed25519.PublicKey)
	copy(s.K[:], []byte(pk))
	s.Target = sha1.Sum(append(s.K[:], s.Salt...))

	bts := s.bufferToSign()
	copy(s.Sig[:], ed25519.Sign(k, bts))

	return nil
}

func (s *Item) IsMutable() bool {
	return len(s.K) > 0
}

func (s *Item) Check() error {
	if !s.IsMutable() {
		m, err := bencode.Marshal(s.V)
		if err != nil {
			return err
		}

		if s.Target != sha1.Sum(m) {
			return ErrBadItem
		}

		return nil
	}

	bts := s.bufferToSign()
	if ok := ed25519.Verify(s.K[:], bts, s.Sig[:]); !ok {
		return ErrBadItem
	}

	return nil
}

func (s *Item) bufferToSign() []byte {
	var bts []byte
	if s.Salt != nil {
		bts = append(bts, []byte("4:salt")...)
		x := bencode.MustMarshal(s.Salt)
		bts = append(bts, x...)
	}
	bts = append(bts, []byte(fmt.Sprintf("3:seqi%de1:v", s.Seq))...)
	bts = append(bts, bencode.MustMarshal(s.V)...)
	return bts
}
