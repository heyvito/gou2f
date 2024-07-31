package hid

func NewBuffer(len int) *Buffer {
	return &Buffer{make([]byte, len), 0}
}

type Buffer struct {
	data []byte
	cur  int
}

func (b *Buffer) Byte(v byte) *Buffer {
	b.data[b.cur] = v
	b.cur++
	return b
}

func (b *Buffer) Int24(v uint32) *Buffer {
	b.data[b.cur+0] = byte(v >> 16)
	b.data[b.cur+1] = byte(v >> 8)
	b.data[b.cur+2] = byte(v)
	b.cur += 3
	return b
}

func (b *Buffer) Data(data []byte) *Buffer {
	copy(b.data[b.cur:], data)
	b.cur += len(data)
	return b
}

func (b *Buffer) Uint32(v uint32) *Buffer {
	b.data[b.cur+0] = byte(v >> 24)
	b.data[b.cur+1] = byte(v >> 16)
	b.data[b.cur+2] = byte(v >> 8)
	b.data[b.cur+3] = byte(v)
	b.cur += 4
	return b
}

func (b *Buffer) Uint16(v uint16) *Buffer {
	b.data[b.cur+0] = byte(v >> 8)
	b.data[b.cur+1] = byte(v)
	b.cur += 2
	return b
}

func (b *Buffer) Bytes(data ...byte) *Buffer {
	copy(b.data[b.cur:], data)
	b.cur += len(data)
	return b
}
