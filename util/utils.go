package util

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

func IpStringToInt64(s string) int64 {
	ret := big.NewInt(0)
	ret.SetBytes(net.ParseIP(s).To4())
	return ret.Int64()
}

func IpIntervalToTargetList(intervals string, ptargetList *[1 << 29]uint8) *[1 << 29]uint8 {
	intervals = strings.TrimSpace(intervals)

	intervalIndex := strings.Index(intervals, "-")
	if intervalIndex < 0 {
		fmt.Println("fail to get index")
		return ptargetList
	}
	startString := strings.TrimSpace(intervals[:intervalIndex])
	if len(startString) == 0 {
		fmt.Println("fail to get start string")
		return ptargetList
	}

	endString := strings.TrimSpace(intervals[intervalIndex+1:])
	if len(endString) == 0 {
		fmt.Println("fail to get end string")
		return ptargetList
	}

	start := IpStringToInt64(startString)
	end := IpStringToInt64(endString)

	for i := start; i < (end + 1); i++ {
		(*ptargetList)[(i / 8)] = (1 << uint8(i%8))
	}

	return ptargetList
}
