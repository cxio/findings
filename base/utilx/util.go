// util-X 工具包
// 收纳一些基础性的加密相关工具函数。
package utilx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"net/netip"
)

// GenerateToken 生成一个随机字节序列。
// @size 目标长度（字节数）
func GenerateToken(size int) ([]byte, error) {
	buf := make([]byte, size)

	rnd, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(size)*8))
	if err != nil {
		return nil, err
	}
	return rnd.FillBytes(buf), nil
}

// HashMAC 创建融入IP的哈希消息码。
// @data 目标数据，哈希的内容。
// @ip 目标IP地址，会剥离IPv4嵌入以容错混用。
func HashMAC_ip(data []byte, ip netip.Addr) [48]byte {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	h := hmac.New(
		sha512.New384,
		ip.AsSlice(),
	)
	h.Write(data)
	return [48]byte(h.Sum(nil))
}

// Hash384 创建融入IP的SHA-384哈希值。
// 注意：此函数与HashMAC_ip不同，它不使用HMAC，而是直接串接计算。
// @data 目标数据，哈希的内容。
// @ip 目标IP地址，会剥离IPv4嵌入以容错混用。
// @return 返回48字节的SHA-384哈希值。
func Hash384(data []byte, ip netip.Addr) [48]byte {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	h := sha512.New384()
	h.Write(ip.AsSlice())
	h.Write(data)

	return [48]byte(h.Sum(nil))
}
