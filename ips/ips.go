package ips

import (
	"log"
	"math/rand"
	"net/netip"
)

// 获取一个随机可用公网IP。
// 仅支持创建为一个IPv4版本的IP，IPv6版暂不支持。
// 可用IP：
// 指排除了私有地址和其它特殊用途的地址。
func randomAddr() netip.Addr {
	var ip netip.Addr
	for {
		// 采用四个0到255之间的随机整数
		ip = netip.AddrFrom4([4]byte{
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
		})
		if isAvailable(ip) {
			break
		}
	}
	return ip
}

// 获取一个随机IP地址集。
// 注：返回的集合中的IP可能有重复。
// @size 想要的集合大小
// @return 随机IP地址集
func randomAddrs(size int) []netip.Addr {
	list := make([]netip.Addr, 0, size)

	for i := 0; i < size; i++ {
		list = append(list, randomAddr())
	}
	return list
}

// 获取某ip临近的一个衍生可用公网IP集。
// 算法会在源ip的前后size范围内寻找，因此返回集是size的两倍。
// 注意：实参ip应当是一个普通公网IP，否则不会执行衍生计算，返回nil。
// @ip 起始点IP（不包含）
// @size 前后搜寻的最大半径
func rangeAddrs(ip netip.Addr, size int) []netip.Addr {
	if !isAvailable(ip) {
		log.Printf("Error IP{%s} is unavailable", ip)
		return nil
	}
	list := make([]netip.Addr, 0, size*2)

	nip := ip
	for i := 0; i < size; i++ {
		nip = nip.Next()
		// 抵达不可用地址时即终止衍生
		// 这是一种概略化处理，因为对返回集并没有严格的要求。
		if !isAvailable(nip) {
			break
		}
		list = append(list, nip)
	}

	pip := ip
	for i := 0; i < size; i++ {
		pip = pip.Prev()
		if !isAvailable(pip) {
			break
		}
		list = append(list, pip)
	}

	return list
}

// 检查是否为可用IP。
// 排除：
// 私有、保留、回环等非公网IP，以及公网全球单播地址。
func isAvailable(ip netip.Addr) bool {
	return ip.IsValid() && !(ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() ||
		ip.IsGlobalUnicast())
}
