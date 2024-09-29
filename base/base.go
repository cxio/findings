// Copyright 2024 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.
// ---------------------------------------------------------------------------
// 基础支持实现及配置。
//
// Date: 2024.08.18 @cxio
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
	CmdFindPing     = "Findings::Ping"     // 本网：可连接测试
	CmdFindOK       = "Findings::OK"       // 本网：服务确认（Findings），应答Ping
	CmdFindBye      = "Findings::ByeBye"   // 本网：结束连接（或查询失败）
	CmdFindHelp     = "Findings::Help"     // 本网：上线协助（初始获取服务器集。临时连接，无关连接池限制）
	CmdFindKinds    = "Findings::Kinds"    // 应用：查询服务器支持的应用类型
	CmdKindOK       = "FindKind::OK"       // 应用：服务器回应目标类型支持：是
	CmdKindFail     = "FindKind::Fail"     // 应用：服务器回应目标类型支持：否
	CmdStunCone     = "__STUN__::Cone"     // STUN：请求NAT类型侦测主服务
	CmdStunSym      = "__STUN__::Sym"      // STUN：请求NAT类型侦测副服务
	CmdStunLive     = "__STUN__::Live"     // STUN：请求NAT存活期侦测服务
	CmdStunHostOK   = "__STUN__::HostOK"   // STUN：第三方主机完成 NewHost 回应
	CmdStunHostFail = "__STUN__::HostFail" // STUN：第三方主机配合 NewHost 失败
)

// 控制指令
type Command byte

// 指令定义
// 本类指令都包含附带的交互数据，指令值和数据会一起打包传输。
const (
	COMMAND_INVALID     Command = iota // 0: 无效类型
	COMMAND_KIND                       // 通用：向服务器声明自己的类型（data: findings|...）
	COMMAND_HELP                       // 本网：服务器发送上线协助数据（临时连接）
	COMMAND_PEER                       // 本网：双方交换Findings节点信息（已有连接）
	COMMAND_JOIN                       // 本网：Findings组网连入（新入连接，含分享交换）
	COMMAND_SERVKINDS                  // 应用：服务器返回自己支持的应用类型名集（data: list）
	COMMAND_APPKIND                    // 应用：应用端向服务器查询是否支持目标应用类型（data: string）
	COMMAND_PEERTCP                    // 应用：请求支持 TCP 直连的节点（data: number）
	COMMAND_SERVPEERTCP                // 应用：服务器返回支持 TCP 直连的节点清单（data: list）
	COMMAND_STUN                       // 应用：应用端请求打洞协助（data: udp-peer）
	COMMAND_PUNCH                      // 应用：服务器提供打洞信令协助（data: list）
	COMMAND_STUN_CONE                  // STUN 回应：NAT类型侦测主服务
	COMMAND_STUN_SYM                   // STUN 回应：NAT类型侦测副服务
	COMMAND_STUN_LIVE                  // STUN 回应：NAT存活期侦测服务
	COMMAND_STUN_HOST                  // STUN 协助：请求对端 NewHost 协助，向所提供的UDP地址发送信号
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
