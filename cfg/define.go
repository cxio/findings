// Copyright 2025 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.
// ---------------------------------------------------------------------------
// 基础配置集
// ----------
// 部分可由用户外部JSON配置修改，部分为程序内置值。
// 大部分配置文件存放于用户主目录下的 .findings/ 之内。
//
// 禁闭节点
// --------
// 程序运行过程中，不友好节点会被临时禁闭排除。
// 用户可以手动设置一个节点清单，内容为简单的地址（IP:Port）列表。
//
// @2025.09.16 cxio
///////////////////////////////////////////////////////////////////////////////
//

// Package cfg 全局配置集
package cfg

import (
	"net/netip"
	"time"
)

// 外部配置默认值。
const (
	UserID      = ""   // 本节点的身份ID（群组时用）
	LogRoot     = ""   // 空值表示使用系统缓存目录
	ServerUport = 7788 // 默认服务端口（UDP）
	ServerTport = 443  // 默认服务端口（TCP，混入方式）
	RemoteUport = 7788 // 远端目标端口（UDP）
	RemoteTport = 443  // 远端目标端口（TCP）
	Shortlist   = 100  // 候选名单长度
	PunchXpool  = 500  // 应用池大小
	ShareXpool  = 1000 // TCP服务器分享池大小
	PeersHelp   = 10   // 上线帮助发送条目数
	PeersPunch  = 5    // 打洞协助连接节点数
	PeersRange  = 200  // 基于起点，节点寻找的范围

	// NAT探测相关
	STUNTest   = true // 是否启动全局 UDP:STUN 探测服务
	NATListen  = 7080 // 本地 NAT 类型探测监听端口
	NATLiving  = 7081 // 本地 NAT 生命期探测监听端口
	ClientOnly = true // 是否需要NAT层级&生存期探测
)

// 开发配置常量
// 部分值关系到安全，不提供外部可配置。
const (
	MaxFinders      = 20                // 组网节点连接数
	SomeFindings    = 10                // 组网分享发送条目数
	AppServerTCP    = 6                 // 应用端请求TCP服务器节点数量
	STUNTryMax      = 4                 // 打洞协助单次失败再尝试最大次数
	BufferSize      = 4096              // 连接读写缓冲区大小
	FinderPatrol    = time.Minute * 10  // 本类节点连接切换巡查间隔
	ShortlistPatrol = time.Minute * 6   // 候选池节点在线巡查间隔
	BanExpired      = time.Hour * 4     // 恶意节点禁闭期限
	ApplierPatrol   = time.Minute * 12  // 应用连接池巡查间隔
	ApplierExpired  = time.Minute * 150 // 应用端在线最长时间（2.5h）
	Punch2Expired   = time.Minute * 30  // 定向打洞目标暂存时长（最大值）
	Punch2Clean     = time.Minute * 60  // 定向打洞目标暂存清理周期
)

// 本系统（findings:z）
const (
	Kind    = "findings" // 基础类别
	AppName = "z"        // 本服务实现名
)

// 几个配置文件
// 大部分在用户主目录内的.findings/子目录下。
const (
	fileDir    = ".findings"    // 配置文件目录
	fileConfig = "config.hjson" // 基础配置文件
	filePeers  = "peers.json"   // 有效节点清单
	fileStakes = "stakes.hjson" // 服务器权益账户配置
	fileBans   = "bans.json"    // 禁闭节点配置
)

// 日志文件名
const (
	LogDir       = "logs"         // 日志根目录（相对于系统缓存根目录）
	LogFile      = "findings.log" // 主程序日志
	LogPeerFile  = "peers.log"    // 有效连接节点历史
	LogDebugFile = "debug.log"    // 调试日志
)

//
//////////////////////////////////////////////////////////////////////////////
//

// Peer 端点类型。
// 仅用于读取用户的节点配置。
type Peer struct {
	IP   netip.Addr `json:"ip"`   // 公网IP
	Port uint16     `json:"port"` // 公网端口
}

func (p *Peer) String() string {
	return netip.AddrPortFrom(p.IP, p.Port).String()
}

// Config 基础配置。
// 通常来说，直接在公网上的节点应当配置 ServerPort 为标准端口7788或443，
// 这样方便新上线的节点寻找。
// RemotePort 用于新节点初始上线时的暴力发现，
// 仅在App内置节点已不可用，且也没有其它可连接的节点配置时才需要。
type Config struct {
	UserID      string `json:"user_id,omitempty"`      // 本节点的身份ID（群组时用）
	LogRoot     string `json:"log_root,omitempty"`     // 日志根目录
	ServerUport uint16 `json:"server_uport,omitempty"` // 服务端口（UDP）
	ServerTport uint16 `json:"server_tport,omitempty"` // 服务端口（TCP，混入方式）
	RemoteUport uint16 `json:"remote_uport,omitempty"` // 远端目标端口（UDP）
	RemoteTport uint16 `json:"remote_tport,omitempty"` // 远端目标端口（TCP）
	Shortlist   int    `json:"shortlist,omitempty"`    // 候选名单长度
	PunchXpool  int    `json:"punch_xpool,omitempty"`  // 应用池大小
	ShareXpool  int    `json:"share_xpool,omitempty"`  // TCP服务器分享池大小
	PeersHelp   int    `json:"peers_help,omitempty"`   // 上线帮助发送条目数
	PeersPunch  int    `json:"peers_punch,omitempty"`  // 打洞协助连接节点数
	PeersRange  int    `json:"peers_range,omitempty"`  // 基于起点，节点寻找的范围
	STUNTest    bool   `json:"stun_on,omitempty"`      // 是否启动全局 UDP:STUN 探测服务
	NATListen   int    `json:"nat_type,omitempty"`     // 本地 NAT 类型探测监听端口
	NATLiving   int    `json:"nat_living,omitempty"`   // 本地 NAT 生命期探测监听端口
	ClientOnly  bool   `json:"client_only,omitempty"`  // 是否需要NAT层级&生存期探测
}
