package stun

import (
	"errors"
	"net"
	"net/netip"

	"google.golang.org/protobuf/proto"
)

// ErrLenSN 序列号长度错误。
var ErrLenSN = errors.New("sn length is bad")

// EncodeServInfo 编码服务端UDP信息
// @port UDP 监听端口
// @sn 随机序列号
// @key 对称加密密钥
// @token 半个密钥因子
func EncodeServInfo(port int, sn, key, token []byte) ([]byte, error) {
	its := &ServInfo{
		Port:  int32(port),
		Sn32:  sn,
		Skey:  key,
		Token: token,
	}
	return proto.Marshal(its)
}

// DecodeServInfo 解码服务端UDP信息
func DecodeServInfo(data []byte) (*ServInfo, error) {
	buf := &ServInfo{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// EncodeLiveNAT 编码LiveNAT的数据
// 其中批次和序列号为明文，地址在protoBuf编码之前会被加密。
// @cnt 发送批次
// @sn 服务器分配的序列号
// @addr 客户端先前的UDP地址（已加密）
// 使用者：客户端
func EncodeLiveNAT(cnt byte, sn ClientSN, port int) ([]byte, error) {
	sn33 := [33]byte{cnt}
	copy(sn33[1:], sn[:])

	buf := &LiveNAT{
		Sn33: sn33[:],
		Port: int32(port),
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
// @return3 目标UDP端口号
func DecodeLiveNAT(data []byte) (byte, ClientSN, int, error) {
	buf := &LiveNAT{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return 0, ClientSN{}, 0, err
	}
	return buf.Sn33[0], ClientSN(buf.Sn33[1:]), int(buf.Port), nil
}

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

// EncodeUDPInfo 编码客户端UDP信息。
func EncodeUDPInfo(addr *net.UDPAddr) ([]byte, error) {
	its := &UDPInfo{
		Ip:   addr.IP,
		Port: int32(addr.Port),
	}
	return proto.Marshal(its)
}

// DecodeUDPInfo 解码客户端UDP信息。
func DecodeUDPInfo(data []byte) (*net.UDPAddr, error) {
	buf := &UDPInfo{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: buf.Ip, Port: int(buf.Port)}, nil
}
