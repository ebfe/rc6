package rc6

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const (
	BlockSize = 16

	_P = uint32(0xb7e15163)
	_Q = uint32(0x9e3779b9)
)

type rc6 struct {
	s []uint32
}

func NewCipher(key []byte) (cipher.Block, error) {

	switch len(key) {
	case 16, 24, 32:
		// nop
	default:
		return nil, errors.New("rc6: invalid key size")
	}

	c := &rc6{}
	c.s = expandkey(key)
	return c, nil
}

func (c *rc6) BlockSize() int {
	return BlockSize
}

func (c *rc6) Encrypt(dst, src []byte) {
	var A, B, C, D uint32

	A = binary.LittleEndian.Uint32(src[0:])
	B = binary.LittleEndian.Uint32(src[4:])
	C = binary.LittleEndian.Uint32(src[8:])
	D = binary.LittleEndian.Uint32(src[12:])

	B += c.s[0]
	D += c.s[1]

	for r := 1; r <= 20; r++ {
		t := rotl(B*(2*B+1), 5)
		u := rotl(D*(2*D+1), 5)
		A = rotl(A^t, u&0x1f) + c.s[2*r]
		C = rotl(C^u, t&0x1f) + c.s[2*r+1]
		A, B, C, D = B, C, D, A
	}

	A += c.s[42]
	C += c.s[43]

	binary.LittleEndian.PutUint32(dst[0:], A)
	binary.LittleEndian.PutUint32(dst[4:], B)
	binary.LittleEndian.PutUint32(dst[8:], C)
	binary.LittleEndian.PutUint32(dst[12:], D)
}

func (c *rc6) Decrypt(dst, src []byte) {
	var A, B, C, D uint32

	A = binary.LittleEndian.Uint32(src[0:])
	B = binary.LittleEndian.Uint32(src[4:])
	C = binary.LittleEndian.Uint32(src[8:])
	D = binary.LittleEndian.Uint32(src[12:])

	C -= c.s[43]
	A -= c.s[42]

	for r := 20; r >= 1; r-- {
		A, B, C, D = D, A, B, C
		u := rotl(D*(2*D+1), 5)
		t := rotl(B*(2*B+1), 5)
		C = rotr(C-c.s[2*r+1], t&0x1f) ^ u
		A = rotr(A-c.s[2*r], u&0x1f) ^ t
	}

	D -= c.s[1]
	B -= c.s[0]

	binary.LittleEndian.PutUint32(dst[0:], A)
	binary.LittleEndian.PutUint32(dst[4:], B)
	binary.LittleEndian.PutUint32(dst[8:], C)
	binary.LittleEndian.PutUint32(dst[12:], D)
}

func expandkey(key []byte) []uint32 {

	l := make([]uint32, len(key)/4)
	for i := range l {
		l[i] = binary.LittleEndian.Uint32(key[i*4:])
	}

	s := make([]uint32, 44)
	s[0] = _P
	for i := 1; i < len(s); i++ {
		s[i] = s[i-1] + _Q
	}

	var a, b, i, j uint32
	for n := uint32(0); n < 132; n++ {
		a = rotl(s[i]+a+b, 3)
		b += a
		b = rotl(l[j]+b, b&0x1f)
		s[i] = a
		l[j] = b
		if i == 43 {
			i = 0
		} else {
			i++
		}
		if j == uint32(len(l)-1) {
			j = 0
		} else {
			j++
		}
	}

	return s
}

func rotl(v, n uint32) uint32 {
	return v<<n | v>>(32-n)
}

func rotr(v, n uint32) uint32 {
	return v>>n | v<<(32-n)
}
