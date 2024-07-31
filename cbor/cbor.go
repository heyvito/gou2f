package cbor

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"math"
)

const majorTypeMask = uint8(0x1F)

type Map []Pair

type Pair struct{ Key, Value any }

func Unmarshal(data []byte) ([]any, error) {
	return UnmarshalReader(bufio.NewReader(bytes.NewReader(data)))
}

func UnmarshalReader(r *bufio.Reader) ([]any, error) {
	dec := NewDecoder(r)
	if err := dec.decode(); err != nil {
		return nil, err
	}
	return dec.objects, nil
}

func UnmarshalOne(data *bufio.Reader) ([]any, error) {
	dec := NewDecoder(data)
	if err := dec.decodeOne(); err != nil {
		return nil, err
	}
	return dec.objects, nil
}

func NewDecoder(data *bufio.Reader) *Decoder {
	return &Decoder{data: data}
}

type Decoder struct {
	objects []any
	data    *bufio.Reader
	cur     int
	lastTag uint64
	isTag   bool
}

var enc = binary.BigEndian

func (d *Decoder) push(v any) {
	if d.isTag {
		d.lastTag = v.(uint64)
		return
	}
	d.objects = append(d.objects, v)
}

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

func (d *Decoder) decode() error {
	for {
		err := d.decodeOne()
		if err == io.EOF {
			return nil
		} else {
			return err
		}
	}
}

func (d *Decoder) decodeOne() error {
	p, err := d.peekMajorType()
	if err != nil {
		return err
	}
	switch p {
	case 0: // unsigned integer
		err = d.parseUnsignedInteger()
	case 1: // negative integer
		err = d.parseNegativeInteger()
	case 2: // byte string
		err = d.parseByteString()
	case 3: // text string
		err = d.parseTextString()
	case 4: // array
		err = d.parseArray()
	case 5: // map of pairs of data items
		err = d.parseMap()
	case 6: // optional semantic tagging of other major types
		d.isTag = true
		err = d.parseUnsignedInteger()
		if err != nil {
			d.isTag = false
		}
	case 7: // floating-point numbers and simple data types that need no content, as well as the "break" stop code.
		err = d.parseMiscValue()
	}

	if err != nil {
		return err
	}

	if d.isTag {
		d.isTag = false
	} else {
		d.lastTag = 0
	}

	return nil
}

func (d *Decoder) parseUnsignedInteger() error {
	p, err := d.pop()
	if err != nil {
		return err
	}
	v := p & majorTypeMask
	if v < 24 {
		if d.isTag {
			d.push(uint64(v))
		} else {
			d.push(uint(v))
		}
		return nil
	}
	switch v {
	case 24:
		p, err = d.pop()
		if err != nil {
			return err
		}
		if d.isTag {
			d.push(uint64(p))
		} else {
			d.push(p)
		}
	case 25:
		a, err := d.take(2)
		if err != nil {
			return err
		}
		if d.isTag {
			d.push(uint64(enc.Uint16(a)))
		} else {
			d.push(enc.Uint16(a))
		}
	case 26:
		a, err := d.take(4)
		if err != nil {
			return err
		}
		if d.isTag {
			d.push(uint64(enc.Uint32(a)))
		} else {
			d.push(enc.Uint32(a))
		}
	case 27:
		a, err := d.take(8)
		if err != nil {
			return err
		}
		d.push(enc.Uint64(a))
	default:
		panic("Invalid CBOR")
	}

	return nil
}

func (d *Decoder) parseNegativeInteger() error {
	p, err := d.pop()
	if err != nil {
		return err
	}
	v := p & majorTypeMask
	if v < 24 {
		d.push(-1 - int(v))
		return nil
	}

	switch v {
	case 24:
		p, err = d.pop()
		if err != nil {
			return err
		}
		d.push(-1 - int(p))
	case 25:
		a, err := d.take(2)
		if err != nil {
			return err
		}
		d.push(-1 - int16(enc.Uint16(a)))
	case 26:
		a, err := d.take(4)
		if err != nil {
			return err
		}
		d.push(-1 - int32(enc.Uint32(a)))
	case 27:
		a, err := d.take(8)
		if err != nil {
			return err
		}
		d.push(-1 - int64(enc.Uint64(a)))
	default:
		panic("Invalid CBOR")
	}

	return nil
}

func (d *Decoder) parseByteString() error {
	p, err := d.pop()
	if err != nil {
		return err
	}
	l := uint64(p & majorTypeMask)
	if l >= 24 {
		switch l {
		case 24:
			p, err = d.pop()
			if err != nil {
				return err
			}
			l = uint64(p)
		case 25:
			a, err := d.take(2)
			if err != nil {
				return err
			}
			l = uint64(enc.Uint16(a))
		case 26:
			a, err := d.take(4)
			if err != nil {
				return err
			}
			l = uint64(enc.Uint32(a))
		case 27:
			a, err := d.take(8)
			if err != nil {
				return err
			}
			l = enc.Uint64(a)
		default:
			panic("Invalid CBOR")
		}
	}

	a, err := d.take(int(l))
	if err != nil {
		return err
	}
	d.push(a)
	return nil
}

func (d *Decoder) parseTextString() error {
	err := d.parseByteString()
	if err != nil {
		return err
	}
	v := d.objects[len(d.objects)-1]
	d.objects[len(d.objects)-1] = string(v.([]byte))
	return nil
}

func (d *Decoder) sub() *Decoder {
	return &Decoder{
		data: d.data,
		cur:  0,
	}
}

func (d *Decoder) parseArray() error {
	p, err := d.pop()
	if err != nil {
		return err
	}
	l := uint64(p & majorTypeMask)
	if l >= 24 {
		switch l {
		case 24:
			p, err = d.pop()
			if err != nil {
				return err
			}
			l = uint64(p)
		case 25:
			a, err := d.take(2)
			if err != nil {
				return err
			}
			l = uint64(enc.Uint16(a))
		case 26:
			a, err := d.take(4)
			if err != nil {
				return err
			}
			l = uint64(enc.Uint32(a))
		case 27:
			a, err := d.take(8)
			if err != nil {
				return err
			}
			l = enc.Uint64(a)
		default:
			panic("Invalid CBOR")
		}
		return nil
	}

	subDecoder := d.sub()

	for range l {
		if err := subDecoder.decodeOne(); err != nil {
			return err
		}
	}

	d.cur += subDecoder.cur

	if d.lastTag == 0x4 || d.lastTag == 0x5 {
		exponent := forceUint64(subDecoder.objects[0])
		mantissa := forceUint64(subDecoder.objects[1])
		v := float64(mantissa) * math.Pow(10, float64(exponent))
		d.push(v)
	} else {
		d.push(subDecoder.objects)
	}
	return nil
}

func forceUint64(v any) int64 {
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

func (d *Decoder) parseMap() error {
	p, err := d.pop()
	if err != nil {
		return err
	}
	l := uint64(p & majorTypeMask)
	if l >= 24 {
		switch l {
		case 24:
			p, err = d.pop()
			if err != nil {
				return err
			}
			l = uint64(p)
		case 25:
			a, err := d.take(2)
			if err != nil {
				return err
			}
			l = uint64(enc.Uint16(a))
		case 26:
			a, err := d.take(4)
			if err != nil {
				return err
			}
			l = uint64(enc.Uint32(a))
		case 27:
			a, err := d.take(8)
			if err != nil {
				return err
			}
			l = enc.Uint64(a)
		default:
			panic("Invalid CBOR")
		}
	}

	sub := d.sub()
	mapVal := Map{}
	for range l {
		if err = sub.decodeOne(); err != nil {
			return err
		}
		if err = sub.decodeOne(); err != nil {
			return err
		}
		mapVal = append(mapVal, Pair{sub.objects[0], sub.objects[1]})
		sub.objects = []any{}
	}

	d.push(mapVal)
	d.cur += sub.cur
	return nil
}

func (d *Decoder) parseMiscValue() error {
	p, err := d.pop()
	if err != nil {
		return err
	}
	value := p & majorTypeMask
	switch {
	case value <= 23: // Simple value (0..23)
		switch value {
		case 20:
			d.push(false)
		case 21:
			d.push(true)
		case 22, 23:
			d.push(nil)
		}
	case value == 24: // Simple value (32..255 in following byte)
		p, err = d.pop()
		if err != nil {
			return err
		}
		d.push(p)
	case value == 25: // IEEE 754 Half-Precision Float (16 bits follow)
		a, err := d.take(2)
		if err != nil {
			return err
		}
		h := uint16(a[0])<<8 | uint16(a[1])
		d.push(decodeHalfPrecisionFloat(h))
	case value == 26: // IEEE 754 Single-Precision Float (32 bits follow)
		a, err := d.take(4)
		if err != nil {
			return err
		}
		h := enc.Uint32(a)
		d.push(math.Float32frombits(h))
	case value == 27: // IEEE 754 Double-Precision Float (64 bits follow)
		a, err := d.take(8)
		if err != nil {
			return err
		}
		h := enc.Uint64(a)
		d.push(math.Float64frombits(h))
	}
	return nil
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
