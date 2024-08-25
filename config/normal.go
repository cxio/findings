// Copyright 2024 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.
// ---------------------------------------------------------------------------
// 通用ProtoBuf数据包一级编解码。
// 该数据包仅包含指令和关联数据的proto编码。
// 目标指令的关联数据需要二次解码，才能还原到其所属的结构。
//
// 注记：
// 这是为了proto编解码不同结构的数据，统一传输用。
// 即不同结构的数据都可以封装在一次websocket读写（ReadMessage/WriteMessage）中。
//
// @2024.08.18 cxio
///////////////////////////////////////////////////////////////////////////////
//

package config

import "google.golang.org/protobuf/proto"

// 控制指令
type Command byte

// 指令定义
// 本类指令都包含附带的交互数据，指令值和数据会一起打包传输。
const (
	COMMAND_INVALID   Command = iota // 0: 无效类型
	COMMAND_HELP                     // 本网：上线协助（初始获取服务器集。临时连接）
	COMMAND_PEER                     // 本网：双方交换节点信息（原有连接）
	COMMAND_JOIN                     // 本网：组网连接（新连接）
	COMMAND_STUN                     // 应用端：请求打洞协助（与其它同类节点连接）
	COMMAND_STUN_CONE                // STUN：回应：NAT类型侦测主服务
	COMMAND_STUN_SYM                 // STUN：回应：NAT类型侦测副服务
	COMMAND_STUN_LIVE                // STUN：回应：NAT存活期侦测服务
)

// EncodeProto 数据编码。
// @name 目标指令
// @data 目标数据（已proto编码）
// @return 待网络传输的编码字节流
func EncodeProto(name Command, data []byte) ([]byte, error) {
	its := &Normal{
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
	buf := &Normal{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return COMMAND_INVALID, nil, err
	}
	return Command(buf.Name), buf.Data, nil
}
