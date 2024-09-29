package stun

import (
	"errors"
	"net"
	"net/netip"

	"google.golang.org/protobuf/proto"
)

// ErrLenSN 序列号长度错误。
var ErrLenSN = errors.New("sn length is bad")

// EncodeHosto 编码客户端UDP信息
// @addr 远端UDP地址
// @sn 标识序列号
func EncodeHosto(addr *net.UDPAddr, sn ClientSN) ([]byte, error) {
	its := &Hosto{
		Ip:   addr.IP,
		Port: int32(addr.Port),
		Sn32: sn[:],
	}
	return proto.Marshal(its)
}

// DecodeHosto 解码客户端UDP编码数据。
func DecodeHosto(data []byte) (*net.UDPAddr, ClientSN, error) {
	buf := &Hosto{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, ClientSN{}, err
	}
	// 可靠性复检
	if _, ok := netip.AddrFromSlice(buf.Ip); !ok {
		return nil, ClientSN{}, ErrParseIP
	}
	if len(buf.Sn32) != LenSN {
		return nil, ClientSN{}, ErrLenSN
	}

	return &net.UDPAddr{IP: buf.Ip, Port: int(buf.Port)}, ClientSN(buf.Sn32), nil
}

// EncodeLiveNAT 编码LiveNAT的数据
// 其中批次和序列号为明文，地址在protoBuf编码之前会被加密。
// @cnt 发送批次
// @sn 服务器分配的序列号
// @addr 客户端先前的UDP地址（已加密）
// 使用者：客户端
func EncodeLiveNAT(cnt uint8, sn ClientSN, addr []byte) ([]byte, error) {
	sn33 := [33]byte{cnt}

	buf := &LiveNAT{
		Sn33:  append(sn33[:1], sn[:]...),
		Xaddr: addr,
	}
	return proto.Marshal(buf)
}

// DecodeLiveNAT 解码/解密LiveNAT编码数据。
// 注意序列号部分为明文，因为需要用此部分来构建密钥。
// 使用者：
// - 由服务器端接收数据后调用。
// - 在验证序列号合法之后，即可解密地址密文（DecryptAddr）。
// @data protoBuf编码的数据
// @return1 发送批次
// @return2 客户端序列号
// @return3 目标地址的密文数据
func DecodeLiveNAT(data []byte) (uint8, ClientSN, []byte, error) {
	buf := &LiveNAT{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return 0, ClientSN{}, nil, err
	}
	return buf.Sn33[0], ClientSN(buf.Sn33[1:]), buf.Xaddr, nil
}
