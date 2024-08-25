package ips

import (
	"log"
	"math/rand"
	"net/netip"
)

// Random 获取一个随机可用公网IP。
// 仅支持创建为一个IPv4版本的IP，IPv6版暂不支持。
// 可用IP：
// 指排除了私有地址和其它特殊用途的地址。
func Random() netip.Addr {
	var ip netip.Addr
	for {
		// 采用四个0到255之间的随机整数
		ip = netip.AddrFrom4([4]byte{
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
			byte(rand.Intn(256)),
		})
		if IsAvailable(ip) {
			break
		}
	}
	return ip
}

// Some 获取某ip临近的一个衍生可用公网IP集。
// size 为返回的IP集的大小（IP数量）。
// 算法会在源ip的前后size范围内寻找（2倍数量），因此返回集只包含部分值。
// 返回集成员的排列是随机的。
// 实参ip应当是一个普通公网IP（IsAvailable），否则不会执行衍生计算，返回nil。
// 注：
// 会指排除私有地址和其它特殊用途的地址。
func Some(ip netip.Addr, size int) []netip.Addr {
	if !IsAvailable(ip) {
		log.Printf("Error IP{%s} is unavailable", ip)
		return nil
	}
	buf := make(map[string]netip.Addr)

	nip := ip
	for n := 0; n < size; n++ {
		nip = nip.Next()
		// 抵达不可用地址时即终止衍生
		// 这是一种概略化处理，因为对返回集并没有严格的要求。
		if !IsAvailable(nip) {
			break
		}
		buf[nip.String()] = nip
	}
	pip := ip
	for n := 0; n < size; n++ {
		// 逆向衍生
		pip = pip.Prev()
		if !IsAvailable(pip) {
			break
		}
		buf[pip.String()] = pip
	}
	i := 0
	list := make([]netip.Addr, 0, size)

	for _, v := range buf {
		if i >= size {
			break
		}
		list = append(list, v)
		i++
	}
	return list
}

// 检查是否为可用IP。
// 排除：私有、保留、回环等非公网IP，以及公网全球单播地址。
func IsAvailable(ip netip.Addr) bool {
	return ip.IsValid() &&
		!(ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsGlobalUnicast())
}
