package node

import (
	"errors"
	"net/netip"

	"google.golang.org/protobuf/proto"
)

// IP 解析错误。
var ErrParseIP = errors.New("parse ip bytes failed")

// EncodePeer 编码节点信息
func EncodePeer(node *Node) ([]byte, error) {
	buf := &Peer{
		Ip:   node.IP.AsSlice(),
		Port: int32(node.Port),
	}
	return proto.Marshal(buf)
}

// DecodePeer 解码节点信息
func DecodePeer(data []byte) (*Node, error) {
	buf := &Peer{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, err
	}
	addr, ok := netip.AddrFromSlice(buf.Ip)
	if !ok {
		return nil, ErrParseIP
	}
	return New(addr, int(buf.Port)), nil
}

// EncodePeers 编码节点集数据
func EncodePeers(nodes []*Node) ([]byte, error) {
	buf := &PeerList{
		Peers: toPeers(nodes),
	}
	return proto.Marshal(buf)
}

// DecodePeers 解码节点集数据
// @data EncodePeers编码的数据。
func DecodePeers(data []byte) ([]*Node, error) {
	plist := &PeerList{}

	if err := proto.Unmarshal(data, plist); err != nil {
		return nil, err
	}
	return toNodes(plist.Peers), nil
}
