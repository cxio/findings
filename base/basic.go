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

// 基础类型名定义。
const (
	BASEKIND_FINDINGS   = "findings"   // Findings 网络节点
	BASEKIND_DEPOTS     = "depots"     // Depots 数据驿站节点（archives|blockqs）
	BASEKIND_BLOCKCHAIN = "blockchain" // 区块链类型应用
	BASEKIND_APP        = "app"        // 非区块链类普通应用
)

// ErrBaseKind 基础类型名错误。
var ErrBaseKind = errors.New("invalid base kind name")

// ErrKindName 应用全名不规范。
var ErrKindName = errors.New("the kind:name not matched")

// 基础类型约束
var baseKinds = map[string]bool{
	BASEKIND_FINDINGS:   true,
	BASEKIND_DEPOTS:     true,
	BASEKIND_BLOCKCHAIN: true,
	BASEKIND_APP:        true,
}

// ParseKind 从普通名称解析为一个Kind
// 如果名称不符合规范（kind:name），则返回nil。
// 如果基础名称不符合规范，也无效，返回nil。
// @kname 冒号分隔的全名称
func ParseKind(name string) (*Kind, error) {
	n2 := strings.SplitN(name, KindSepartor, 2)

	if len(n2) < 2 {
		return nil, ErrKindName
	}
	if !baseKinds[n2[0]] {
		return nil, ErrBaseKind
	}
	return &Kind{Base: n2[0], Name: n2[1]}, nil
}

// KindName 创建类型的全名称
func KindName(kname *Kind) string {
	return kname.Base + KindSepartor + kname.Name
}

// EncodeKind 编码服务类型名
// 会自动检查基础类别名称是否合法。
// @base 基础名（depots|blockchain|app|""）
// @name 具体名称
// 注记：
// base 为空时，name 仅适用 findings 名称。
func EncodeKind(base, name string) ([]byte, error) {
	if !baseKinds[base] {
		return nil, ErrBaseKind
	}
	buf := &Kind{
		Base: base,
		Name: name,
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

// EncodeProto 数据解码
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
