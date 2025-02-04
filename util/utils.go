package util

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"runtime"
)

func GoroutineID() int {
	return runtime.NumGoroutine()
}

func EncodeSocketInfo(srcIP []byte, srcPort uint16, dstIP []byte, dstPort uint16) uint16 {
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, srcIP)
	binary.Write(bytebuf, binary.BigEndian, srcPort)
	binary.Write(bytebuf, binary.BigEndian, dstIP)
	binary.Write(bytebuf, binary.BigEndian, dstPort)

	retByte := md5.Sum(bytebuf.Bytes())
	ret := binary.BigEndian.Uint16(retByte[:])
	// ret = ret & ((1 << 18) - 1)
	return ret
}
