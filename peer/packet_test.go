// SPDX-License-Identifier: MIT

package peer

func benchPackets(batch, size int) []Packet {
	const stride = 1536
	slab := make([]byte, batch*stride)
	packets := make([]Packet, batch)
	for i := range packets {
		packets[i] = Packet{Buffer: slab[i*stride : (i+1)*stride : (i+1)*stride], Offset: 40, Size: size}
	}
	return packets
}

func resetPackets(packets []Packet, size int) {
	for i := range packets {
		packets[i].Offset = 40
		packets[i].Size = size
	}
}
