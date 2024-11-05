// Copyright 2024 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.
// ---------------------------------------------------------------------------
// basec.pb.go 的编解码实现。
//
// Date: 2024.09.20
///////////////////////////////////////////////////////////////////////////////

package base

import (
	"errors"
	"strings"

	"google.golang.org/protobuf/proto"
)

// KindSepartor 基础名:具体名的分隔符
const KindSepartor = ":"

// 应用所属的类别。
// 此为应用端向服务器发送的最初数据，用于声明自己。
const (
	KIND_FINDINGS   = "findings"   // 类别：Findings 网络节点
	KIND_DEPOTS     = "depots"     // 类别：Depots 数据驿站节点（archives|blockqs）
	KIND_BLOCKCHAIN = "blockchain" // 类别：区块链类型应用
	KIND_APP        = "app"        // 类别：非区块链类普通应用
)

// 寻求的服务类型
// SEEK_ASSISTX: 服务器向客户端发送一个Peer集合。Command: COMMAND_HELP
// SEEK_KINDAPP: 服务器发送一个Kind集合。Command: COMMAND_KINDLIST
// SEEK_PEERTCP: 如果失败，服务器向客户端回应一个错误消息，否则仅为一个CmdFindBye。
const (
	SEEK_FINDNET = "find:net" // 寻求：Findings组网
	SEEK_ASSISTX = "assist:x" // 寻求：上线协助
	SEEK_APPSERV = "stun:nat" // 寻求：应用服务（NAT探测&打洞协助）
	SEEK_KINDAPP = "kind:app" // 寻求：应用支持清单
	SEEK_PEERTCP = "peer:tcp" // 寻求：登记TCP服务器（可直连）
)

// ErrBaseKind 基础类型名错误。
var ErrBaseKind = errors.New("invalid base kind name")

// ErrKindName 应用全名不规范。
var ErrKindName = errors.New("the kind:name not matched")

// 基础类型约束
var baseKinds = map[string]bool{
	KIND_FINDINGS:   true,
	KIND_DEPOTS:     true,
	KIND_BLOCKCHAIN: true,
	KIND_APP:        true,
}

// Name2Kind 从普通名称解析为一个Kind
// 如果名称不符合规范（kind:name），则返回nil。
// 如果基础名称不符合规范，也无效，返回nil。
// @kname 冒号分隔的全名称
// @seek 请求类别，在此为占位符（可传递空串）
func Name2Kind(name, seek string) (*Kind, error) {
	n2 := strings.SplitN(name, KindSepartor, 2)

	if len(n2) < 2 {
		return nil, ErrKindName
	}
	if !baseKinds[n2[0]] {
		return nil, ErrBaseKind
	}
	return &Kind{Base: n2[0], Name: n2[1], Seek: seek}, nil
}

// KindName 创建类型的全名称
func KindName(base, name string) string {
	return base + KindSepartor + name
}

// EncodeKind 编码服务类型名
// 会自动检查基础类别名称是否合法。
// @base 基础名（depots|blockchain|app|findings）
// @name 具体名称
// @seek 寻求的帮助（组网：finder | 应用服务：applier | 上线协助：assist）
func EncodeKind(base, name, seek string) ([]byte, error) {
	if !baseKinds[base] {
		return nil, ErrBaseKind
	}
	buf := &Kind{
		Base: base,
		Name: name,
		Seek: seek,
	}
	return proto.Marshal(buf)
}

// DecodeKind 解码服务类型名
// 会自动检查基础类别名称是否合法。
// @return1 基础名
// @return2 具体特定名
func DecodeKind(data []byte) (*Kind, error) {
	buf := &Kind{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, err
	}
	if !baseKinds[buf.Base] {
		return nil, ErrBaseKind
	}
	return buf, nil
}

// EncodeServKinds 编码服务类型名清单。
func EncodeServKinds(kinds []*Kind) ([]byte, error) {
	buf := &ServKinds{
		Names: kinds,
	}
	return proto.Marshal(buf)
}

// DecodeServKinds 解码服务类型名清单。
func DecodeServKinds(data []byte) ([]*Kind, error) {
	list := &ServKinds{}

	if err := proto.Unmarshal(data, list); err != nil {
		return nil, err
	}
	return list.Names, nil
}

// EncodeStake 编码收益信息
func EncodeStake(id, addr string) ([]byte, error) {
	buf := &Stake{
		Id:   id,
		Addr: addr,
	}
	return proto.Marshal(buf)
}

// DecodeStake 解码收益信息
// @return1 身份ID
// @return2 收益地址
func DecodeStake(data []byte) (string, string, error) {
	buf := &Stake{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return "", "", err
	}
	return buf.Id, buf.Addr, nil
}

//
// 通用ProtoBuf数据包一级编解码。
// 该数据包仅包含指令和关联数据的proto编码。
// 目标指令的关联数据需要二次解码，才能还原到其所属的结构。
//
// 注记：
// 这是为了proto编解码不同结构的数据，统一传输用。
// 即不同结构的数据都可以封装在一次websocket读写（ReadMessage/WriteMessage）中。
//////////////////////////////////////////////////////////////////////////////
//

// EncodeProto 数据编码。
// @name 目标指令
// @data 目标数据（已proto编码）
// @return 待网络传输的编码字节流
func EncodeProto(name Command, data []byte) ([]byte, error) {
	its := &Proto{
		Name: int32(name),
		Data: data,
	}
	return proto.Marshal(its)
}

// DecodeProto 数据解码
// @data 初始接收的proto编码字节流
// @return1 数据类型
// @return2 该类型的编码数据（proto）
func DecodeProto(data []byte) (Command, []byte, error) {
	buf := &Proto{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return COMMAND_INVALID, nil, err
	}
	return Command(buf.Name), buf.Data, nil
}
