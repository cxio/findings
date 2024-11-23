// Copyright 2024 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.
// ---------------------------------------------------------------------------
// 基础支持实现及配置。
//
// 使用
// ====
// 用户客户端在创建与服务器的websocket连接后，使用特定的指令进行沟通、获取服务。
// 其中：
// COMMAND_KIND 为用户首先使用的指令，声明自己的类别和应用名，以及目的。
// 之后，使用其它指令获取相应的服务。
//
// 指令包含两种：
// 1. 无需携带数据的简单指令，为文本格式（.TextMessage），发送即可。
// 2. 需要携带数据的指令，为二进制形式编码（.BinaryMessage），需借助于编解码函数。
// 详见下面内容。
//
// 数据指令
// ========
// 下面为数据指令名及数据流向和简单说明。
// 数据的使用请查看 protobuf/ 文件夹内的消息定义文件，以及相应的编解码函数。
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
// COMMAND_PUNCH:		<=| stun.Punchx{ "", IP, Port...}
// COMMAND_PUNCH2:		<=| stun.PunchOne{ "", IP, Port...}
// COMMAND_PUNCHX:		|=> stun.Punchx{ Dir, Ip, Port... } ...
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
	"context"
	"log"

	"github.com/cxio/findings/config"
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
	COMMAND_PUNCH                    // 应用：应用端请求打洞协助（data: udp-peer）
	COMMAND_PUNCH2                   // 应用：应用端登记或请求定向打洞协助（data: udp-peer, [target]）
	COMMAND_PUNCHX                   // 应用：服务器提供打洞信令协助（data: udp-peer）
	COMMAND_STUN_CONE                // STUN：服务器回应NAT类型侦测主服务
	COMMAND_STUN_SYM                 // STUN：服务器回应NAT类型侦测副服务
	COMMAND_STUN_PEER                // STUN：服务器回应对端UDP节点信息
	COMMAND_STUN_LIVE                // STUN：服务器回应NAT存活期侦测服务
	COMMAND_STUN_HOST                // STUN：请求对端NewHost协助，向其提供UDP地址
)

// 全局随机种子
// 程序每次启动后自动创建，当前运行时固定。
var GlobalSeed [32]byte

// 相应几个日志记录器
var (
	Log      *log.Logger // 通用记录
	LogPeer  *log.Logger // 有效连接节点历史
	LogDebug *log.Logger // 调试专用记录
)

// LogsInit 日志初始化。
// 创建3个基本日志记录器，外部直接使用即可。
// 当外部的上下文环节退出时，即关闭日志。
// @ctx 执行上下文
// @logs 日志存放根目录
func LogsInit(ctx context.Context, logs string) {
	// 主记录，含错误和警告
	log1, f1, err := config.CreateLoger(logs, config.LogFile, "")
	if err != nil {
		log.Fatalf("Failed to create log file %v\n", err)
	}
	go func() {
		<-ctx.Done()
		f1.Close()
	}()
	// 节点历史存留
	log2, f2, err := config.CreateLoger(logs, config.LogPeerFile, "[Peer] ")
	if err != nil {
		log.Fatalf("Failed to create log file %v\n", err)
	}
	go func() {
		<-ctx.Done()
		f2.Close()
	}()
	// 调试专用
	log3, f3, err := config.CreateLoger(logs, config.LogDebugFile, "[Debug] ")
	if err != nil {
		log.Fatalf("Failed to create log file %v\n", err)
	}
	go func() {
		<-ctx.Done()
		f3.Close()
	}()
	// 全局赋值
	Log, LogPeer, LogDebug = log1, log2, log3
}

func init() {
	seed, err := utilx.GenerateToken(32)

	if err != nil {
		log.Fatalln("generate service token failed on init.")
	}
	GlobalSeed = [32]byte(seed)
}
