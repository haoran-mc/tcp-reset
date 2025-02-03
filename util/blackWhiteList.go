package util

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var (
	BlackTargetList *[1 << 29]uint8
	WhiteTargetList *[1 << 29]uint8
)

func GetTargetList(path string) {
	BlackTargetList = new([1 << 29]uint8)
	WhiteTargetList = new([1 << 29]uint8)

	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		s := strings.TrimSpace(string(b))

		index := strings.Index(s, "=")
		if index < 0 {
			continue
		}
		key := strings.TrimSpace(s[:index])
		if len(key) == 0 {
			continue
		}

		value, err := strconv.Atoi(strings.TrimSpace(s[index+1:]))
		if err != nil {
			fmt.Println("Read target label error", err.Error())
			continue
		}

		index = strings.Index(key, "-")
		if index < 0 {
			key8 := IpStringToInt64(key) / 8
			keymod8 := IpStringToInt64(key) % 8

			if value == 0 {
				(*BlackTargetList)[key8] = (1 << uint8(keymod8))
				continue
			} else if value == 1 {
				(*WhiteTargetList)[key8] = (1 << uint8(keymod8))
				continue
			}
			continue
		} else if index > -1 {
			if value == 0 {
				BlackTargetList = IpIntervalToTargetList(key, BlackTargetList)
				continue
			} else if value == 1 {
				WhiteTargetList = IpIntervalToTargetList(key, WhiteTargetList)
				continue
			}
			continue
		}
	}

	fmt.Println("Get targets,lens: ", len(*WhiteTargetList), len(*WhiteTargetList))
}
