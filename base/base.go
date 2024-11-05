// Copyright 2024 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.
// ---------------------------------------------------------------------------
// 基础支持实现及配置。
//
// 指令：			数据 （服务器 <=> 客户端）
// ------------------------------------------------------------------
// COMMAND_KIND: 		<=| Kind{ Base, Name, Seek }
// COMMAND_HELP:		|=> []node.Peer{ Ip, Port }
// COMMAND_PEER:		<=> []node.Peer{ Ip, Port }
// COMMAND_STAKE:		|=> []byte
// COMMAND_KINDLIST:		|=> []Kind{ Base, Name }
// COMMAND_APPKIND:		<=| Kind{ Base, Name }
// COMMAND_PEERSTCP:		|=> []node.Peer { Ip, Port }
// COMMAND_STUN:		<=| stun.Appinfo{ Base, Name, IP, Port...}
// COMMAND_PUNCH:		|=> stun.Punchx{ Dir, Ip, Port... } ...
// COMMAND_STUN_CONE:		|=> stun.ServInfo{ Port, Sn32, Skey, Token }
// COMMAND_STUN_SYM:		|=> stun.ServInfo{ ... }
// COMMAND_STUN_PEER:		|=> stun.UDPInfo{ Ip, Port }
// COMMAND_STUN_LIVE:		|=> stun.ServInfo{ ... }
// COMMAND_STUN_HOST:		<=| stun.Hosto { Ip, Port, Sn32 }
//
// Date: 2024.11.01 @cxio
///////////////////////////////////////////////////////////////////////////////

// base 基础支持包
package base

import (
	"log"

	"github.com/cxio/findings/crypto/utilx"
)

// 简单指令（无数据）
// 用文本形式有更好的可辨识性，避免简单数字可能的误撞。
const (
	CmdFindPing = "Findings::Ping"   // 本网：可连接测试
	CmdFindOK   = "Findings::OK"     // 本网：服务确认（Findings），应答Ping
	CmdFindBye  = "Findings::ByeBye" // 本网：结束连接（或查询失败）
	CmdKindOK   = "FindKind::OK"     // 应用：服务器回应目标类型支持：是
	CmdKindFail = "FindKind::Fail"   // 应用：服务器回应目标类型支持：否
	CmdAppsTCP  = "FindApps::TCP"    // 应用：客户端请求可直连TCP服务器节点信息
	CmdStunCone = "__STUN__::Cone"   // STUN：请求NAT类型侦测主服务
	CmdStunSym  = "__STUN__::Sym"    // STUN：请求NAT类型侦测副服务
	CmdStunLive = "__STUN__::Live"   // STUN：请求NAT存活期侦测服务
)

// 控制指令
type Command byte

// 指令定义
// 本类指令都包含附带的交互数据，指令值和数据会一起打包传输。
const (
	COMMAND_INVALID   Command = iota // 0: 无效类型
	COMMAND_KIND                     // 通用：初始向服务器声明自己的请求种类
	COMMAND_HELP                     // 本网：服务器发送上线协助数据（临时连接）
	COMMAND_PEER                     // 本网：双方交换Findings节点信息
	COMMAND_STAKE                    // 应用：服务器传送的相应类型的权益地址
	COMMAND_KINDLIST                 // 应用：服务器返回自己支持的应用类型（data: list）
	COMMAND_APPKIND                  // 应用：应用端向服务器查询是否支持目标应用类型
	COMMAND_PEERSTCP                 // 应用：服务器返回支持 TCP 直连的节点清单（data: list）
	COMMAND_STUN                     // 应用：应用端请求打洞协助（data: udp-peer）
	COMMAND_PUNCH                    // 应用：服务器提供打洞信令协助（data: udp-peer）
	COMMAND_STUN_CONE                // STUN：服务器回应NAT类型侦测主服务
	COMMAND_STUN_SYM                 // STUN：服务器回应NAT类型侦测副服务
	COMMAND_STUN_PEER                // STUN：服务器回应对端UDP节点信息
	COMMAND_STUN_LIVE                // STUN：服务器回应NAT存活期侦测服务
	COMMAND_STUN_HOST                // STUN：请求对端NewHost协助，向其提供UDP地址
)

// 全局随机种子
// 程序每次启动后自动创建，当前运行时固定。
var GlobalSeed [32]byte

func init() {
	seed, err := utilx.GenerateToken(32)

	if err != nil {
		log.Fatalln("generate service token failed on init.")
	}
	GlobalSeed = [32]byte(seed)
}