package buffer

import "sync"

const (
	min = 2 << 10
	mid = 10 << 10
	max = 65 << 10
)

var _ Source = (*FragmentPool)(nil)

type FragmentPool struct {
	minPool sync.Pool
	midPool sync.Pool
	maxPool sync.Pool
}

func NewFragmentPool() *FragmentPool {
	recycle := func(p *sync.Pool) func(*Buffer) {
		return func(b *Buffer) {
			b.data = b.data[:cap(b.data)]
			p.Put(b)
		}
	}
	p := new(FragmentPool)
	p.minPool.New = func() any {
		return &Buffer{data: make([]byte, min), recycle: recycle(&p.minPool)}
	}
	p.midPool.New = func() any {
		return &Buffer{data: make([]byte, mid), recycle: recycle(&p.midPool)}
	}
	p.maxPool.New = func() any {
		return &Buffer{data: make([]byte, max), recycle: recycle(&p.maxPool)}
	}
	return p
}

func (p *FragmentPool) Get(size int) *Buffer {
	var buf *Buffer
	switch {
	case size <= min:
		buf = p.minPool.Get().(*Buffer)
	case size <= mid:
		buf = p.midPool.Get().(*Buffer)
	case size <= max:
		buf = p.maxPool.Get().(*Buffer)
	default:
		return &Buffer{data: make([]byte, size)}
	}
	buf.data = buf.data[:size]
	return buf
}
