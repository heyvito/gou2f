package cbor

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const majorTypeMask = uint8(0x1F)

type Map []Pair

func (m Map) FindKey(key any) *Pair {
	for _, v := range m {
		if v.Key == key {
			return &v
		}
	}

	return nil
}

func MapGetKey[T any](m Map, k any) (r T, ok bool) {
	for _, pair := range m {
		if pair.Key == k {
			r, ok = pair.Value.(T)
			return
		}
	}
	return
}

type Pair struct{ Key, Value any }

func NewDecoder(data *bufio.Reader) *Decoder {
	return &Decoder{data: data}
}

type Decoder struct {
	data    *bufio.Reader
	cur     int
	lastTag uint64
	isTag   bool
}

var enc = binary.BigEndian

func (d *Decoder) peek() (byte, error) {
	p, err := d.data.Peek(1)
	if err != nil {
		return 0, err
	}
	return p[0], nil
}

func (d *Decoder) pop() (byte, error) {
	b, err := d.data.ReadByte()
	if err != nil {
		return 0, err
	}
	d.cur++
	return b, nil
}

func (d *Decoder) take(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := d.data.Read(data)
	if err != nil {
		return nil, err
	}
	d.cur += size
	return data, nil
}

func (d *Decoder) peekMajorType() (byte, error) {
	b, err := d.peek()
	if err != nil {
		return 0, err
	}
	return b >> 5, nil
}

func (d *Decoder) decode() (any, error) {
	for {
		v, err := d.decodeOne()
		if err == io.EOF {
			return v, nil
		} else {
			return v, err
		}
	}
}

func (d *Decoder) decodeOne() (any, error) {
	p, err := d.peekMajorType()
	if err != nil {
		return nil, err
	}
	var v any
	switch p {
	case 0: // unsigned integer
		v, err = d.parseUnsignedInteger()
	case 1: // negative integer
		v, err = d.parseNegativeInteger()
	case 2: // byte string
		v, err = d.parseByteString()
	case 3: // text string
		v, err = d.parseTextString()
	case 4: // array
		v, err = d.parseArray()
	case 5: // map of pairs of data items
		v, err = d.parseMap()
	case 6: // optional semantic tagging of other major types
		d.isTag = true
		v, err = d.parseUnsignedInteger()
		if err != nil {
			d.isTag = false
		}
	case 7: // floating-point numbers and simple data types that need no content, as well as the "break" stop code.
		v, err = d.parseMiscValue()
	}

	if err != nil {
		return nil, err
	}

	if d.isTag {
		d.isTag = false
	} else {
		d.lastTag = 0
	}

	return v, nil
}

func (d *Decoder) parseUnsignedInteger() (uint64, error) {
	p, err := d.pop()
	if err != nil {
		return 0, err
	}
	v := p & majorTypeMask
	if v < 24 {
		return uint64(v), err
	}
	switch v {
	case 24:
		p, err = d.pop()
		if err != nil {
			return 0, err
		}

		return uint64(p), nil

	case 25:
		a, err := d.take(2)
		if err != nil {
			return 0, err
		}
		return uint64(enc.Uint16(a)), nil

	case 26:
		a, err := d.take(4)
		if err != nil {
			return 0, err
		}

		return uint64(enc.Uint32(a)), nil
	case 27:
		a, err := d.take(8)
		if err != nil {
			return 0, err
		}
		return enc.Uint64(a), nil
	}

	return 0, fmt.Errorf("invalid CBOR")
}

func (d *Decoder) parseNegativeInteger() (int64, error) {
	p, err := d.pop()
	if err != nil {
		return 0, err
	}
	v := p & majorTypeMask
	if v < 24 {
		return -1 - int64(v), nil
	}

	switch v {
	case 24:
		p, err = d.pop()
		if err != nil {
			return 0, err
		}
		return int64(-1 - int(p)), nil

	case 25:
		a, err := d.take(2)
		if err != nil {
			return 0, err
		}
		return int64(-1 - int16(enc.Uint16(a))), nil

	case 26:
		a, err := d.take(4)
		if err != nil {
			return 0, err
		}
		return int64(-1 - int32(enc.Uint32(a))), nil

	case 27:
		a, err := d.take(8)
		if err != nil {
			return 0, err
		}
		return -1 - int64(enc.Uint64(a)), nil

	}

	return 0, fmt.Errorf("invalid cbor")
}

func (d *Decoder) parseByteString() ([]byte, error) {
	p, err := d.pop()
	if err != nil {
		return nil, err
	}
	l := uint64(p & majorTypeMask)
	if l >= 24 {
		switch l {
		case 24:
			p, err = d.pop()
			if err != nil {
				return nil, err
			}
			l = uint64(p)
		case 25:
			a, err := d.take(2)
			if err != nil {
				return nil, err
			}
			l = uint64(enc.Uint16(a))
		case 26:
			a, err := d.take(4)
			if err != nil {
				return nil, err
			}
			l = uint64(enc.Uint32(a))
		case 27:
			a, err := d.take(8)
			if err != nil {
				return nil, err
			}
			l = enc.Uint64(a)
		default:
			panic("Invalid CBOR")
		}
	}

	a, err := d.take(int(l))
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (d *Decoder) parseTextString() (string, error) {
	data, err := d.parseByteString()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (d *Decoder) sub() *Decoder {
	return &Decoder{
		data: d.data,
		cur:  0,
	}
}

func (d *Decoder) parseArray() (any, error) {
	p, err := d.pop()
	if err != nil {
		return nil, err
	}
	l := uint64(p & majorTypeMask)
	if l >= 24 {
		switch l {
		case 24:
			p, err = d.pop()
			if err != nil {
				return nil, err
			}
			l = uint64(p)
		case 25:
			a, err := d.take(2)
			if err != nil {
				return nil, err
			}
			l = uint64(enc.Uint16(a))
		case 26:
			a, err := d.take(4)
			if err != nil {
				return nil, err
			}
			l = uint64(enc.Uint32(a))
		case 27:
			a, err := d.take(8)
			if err != nil {
				return nil, err
			}
			l = enc.Uint64(a)
		default:
			return nil, fmt.Errorf("invalid CBOR")
		}
	}

	subDecoder := d.sub()

	arr := make([]any, l)
	for i := range l {
		a, err := subDecoder.decodeOne()
		if err != nil {
			return nil, err
		}
		arr[i] = a
	}

	d.cur += subDecoder.cur

	if d.lastTag == 0x4 || d.lastTag == 0x5 {
		exponent := forceInt64(arr[0])
		mantissa := forceInt64(arr[1])
		return float64(mantissa) * math.Pow(10, float64(exponent)), nil
	}

	return arr, nil
}

func forceInt64(v any) int64 {
	switch v := v.(type) {
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		return int64(v)
	case int:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	default:
		panic("Can't convert to uint64")
	}
}

func (d *Decoder) parseMap() (Map, error) {
	p, err := d.pop()
	if err != nil {
		return nil, err
	}
	l := uint64(p & majorTypeMask)
	if l >= 24 {
		switch l {
		case 24:
			p, err = d.pop()
			if err != nil {
				return nil, err
			}
			l = uint64(p)
		case 25:
			a, err := d.take(2)
			if err != nil {
				return nil, err
			}
			l = uint64(enc.Uint16(a))
		case 26:
			a, err := d.take(4)
			if err != nil {
				return nil, err
			}
			l = uint64(enc.Uint32(a))
		case 27:
			a, err := d.take(8)
			if err != nil {
				return nil, err
			}
			l = enc.Uint64(a)
		default:
			panic("Invalid CBOR")
		}
	}

	sub := d.sub()
	mapVal := Map{}
	for range l {
		key, err := sub.decodeOne()
		if err != nil {
			return nil, err
		}
		val, err := sub.decodeOne()
		if err != nil {
			return nil, err
		}
		mapVal = append(mapVal, Pair{key, val})
	}

	d.cur += sub.cur
	return mapVal, nil
}

func (d *Decoder) parseMiscValue() (any, error) {
	p, err := d.pop()
	if err != nil {
		return nil, err
	}
	value := p & majorTypeMask
	switch {
	case value <= 23: // Simple value (0..23)
		switch value {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		}
	case value == 24: // Simple value (32..255 in following byte)
		p, err = d.pop()
		if err != nil {
			return nil, err
		}
		return p, nil
	case value == 25: // IEEE 754 Half-Precision Float (16 bits follow)
		a, err := d.take(2)
		if err != nil {
			return nil, err
		}
		h := uint16(a[0])<<8 | uint16(a[1])
		return decodeHalfPrecisionFloat(h), nil
	case value == 26: // IEEE 754 Single-Precision Float (32 bits follow)
		a, err := d.take(4)
		if err != nil {
			return nil, err
		}
		h := enc.Uint32(a)
		return math.Float32frombits(h), nil
	case value == 27: // IEEE 754 Double-Precision Float (64 bits follow)
		a, err := d.take(8)
		if err != nil {
			return nil, err
		}
		h := enc.Uint64(a)
		return math.Float64frombits(h), nil
	}
	return nil, nil
}

func decodeHalfPrecisionFloat(h uint16) float32 {
	const (
		halfFracMask = 0x03FF
		halfExpBias  = 15
		halfMaxExp   = 31

		singleExpMask = 0x7F800000
		singleExpBias = 127
	)

	sign := uint32(h>>15) & 0x1
	exp := uint32(h>>10) & 0x1F
	frac := uint32(h) & halfFracMask

	var result uint32
	if exp == 0 {
		if frac == 0 {
			result = sign << 31
		} else {
			exp := singleExpBias - halfExpBias + 1
			for frac&0x0400 == 0 {
				frac <<= 1
				exp--
			}
			frac &= halfFracMask
			result = (sign << 31) | uint32(exp<<23) | (frac << 13)
		}
	} else if exp == halfMaxExp {
		if frac == 0 {
			result = (sign << 31) | singleExpMask
		} else {
			result = (sign << 31) | singleExpMask | (frac << 13)
		}
	} else {
		exp = exp + singleExpBias - halfExpBias
		result = (sign << 31) | (exp << 23) | (frac << 13)
	}

	return math.Float32frombits(result)
}
