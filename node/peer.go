package node

import "google.golang.org/protobuf/proto"

// EncodePeers 编码节点数据
// 内部实际上是使用 Peer 的 proto 定义。
// 注记：
// 结果数据中包含了封装切片的父结构 Peers{[]*Peer}。
func EncodePeers(nodes []*Node) ([]byte, error) {
	buf := &PeerList{
		Peers: toPeers(nodes),
	}
	return proto.Marshal(buf)
}

// DecodePeers 解码节点数据
// 内部将封装在Peers中的切片数据提取出来。
// 注：data 为 EncodePeers 编码的数据。
func DecodePeers(data []byte) ([]*Node, error) {
	peerlist := &PeerList{}

	if err := proto.Unmarshal(data, peerlist); err != nil {
		return nil, err
	}
	return toNodes(peerlist.Peers), nil
}
