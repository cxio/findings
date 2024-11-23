// Copyright 2024 of chainx.zh@gmail.com, All rights reserved.
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
// 用户也可以配置一个节点清单，但它们也遵循同样的时效期。
// 禁闭配置文件（bans.json）在应用程序系统缓存目录下，如果不存在可手工创建。
// 内容为简单的地址（IP:Port）清单。
//
// @2024.11.23 cxio
///////////////////////////////////////////////////////////////////////////////
//

// Package config 全局配置集
package config

import (
	"net/netip"
	"time"
)

// 基本配置常量。
const (
	UserID         = ""   // 本节点的身份ID（群组时用）
	ServerPort     = 7788 // 默认服务端口（TCP）
	RemotePort     = 7788 // 远端目标端口（TCP）
	UDPListen      = 7080 // 本地 NAT 类型探测监听端口
	UDPLiving      = 7181 // 本地 NAT 生命期探测监听端口
	MaxFinders     = 10   // 组网节点连接数
	PeersHelp      = 8    // 上线协助发送条目数
	MaxApps        = 500  // 每种应用默认的节点连接数上限
	ListFindings   = 40   // 本类节点候选名单长度
	BufferSize     = 1024 // 连接读写缓冲区大小
	PeerFindRange  = 200  // 节点寻找的范围（基于起点）
	STUNPeerAmount = 5    // 打洞协助连系的节点数
	STUNLiving     = true // 是否启动 STUN:Live 服务（NAT生命期探测）
	STUNClient     = true // 是否需要NAT层级&生存期探测
)

// 开发配置常量
// 部分值关系到安全性，不提供外部可配置。
const (
	SomeFindings    = 10                // 本类端组网发送条目数
	AppServerTCP    = 6                 // 应用端请求TCP服务器节点数量
	STUNTryMax      = 4                 // 打洞协助单次失败再尝试最大次数
	FinderPatrol    = time.Minute * 10  // 本类节点连接切换巡查间隔
	ShortlistPatrol = time.Minute * 6   // 后续池节点在线巡查间隔
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
// 对于处于NAT之后的内网节点，端口是任意的，它们通常作为在候选名单或当前连接的已知节点存在。
// RemotePort 用于新节点初始上线时的暴力发现，
// 仅在App内置节点已不可用，且也没有其它可连接的节点配置时才需要。
type Config struct {
	UserID         string `json:"user_id"`               // 本节点的身份ID（群组时用）
	ServerPort     int    `json:"server_port"`           // 本地服务端口
	RemotePort     int    `json:"remote_port,omitempty"` // 远端节点服务端口（7788|443|0|...）
	UDPListen      int    `json:"udp_listen"`            // 本地 NAT 类型探测监听端口
	UDPLiving      int    `json:"udp_living"`            // 本地 NAT 生命期探测监听端口
	LogDir         string `json:"log_dir"`               // 日志根目录
	Findings       int    `json:"findings"`              // 同时连接的本类节点数
	PeersHelp      int    `json:"peers_help"`            // 上线帮助发送条目数
	ConnApps       int    `json:"applications"`          // 可同时连接的应用端数量上限
	Shortlist      int    `json:"shortlist"`             // 本类节点候选名单长度
	BufferSize     int    `json:"buffer_size,omitempty"` // 连接读写缓冲区大小
	PeerFindRange  int    `json:"peers_range"`           // 基于起点，节点寻找的范围
	STUNPeerAmount int    `json:"stun_peer_amount"`      // 打洞协助连接节点数
	STUNLiving     bool   `json:"stun_living"`           // 是否启动全局 UDP:STUN 服务
	STUNClient     bool   `json:"stun_client"`           // 是否需要NAT层级&生存期探测
}
