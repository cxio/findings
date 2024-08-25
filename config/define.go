// Copyright 2024 of chainx.zh@gmail.com, All rights reserved.
// Use of this source code is governed by a MIT license.
// ---------------------------------------------------------------------------
//
//
// @2024.05.14 cxio
///////////////////////////////////////////////////////////////////////////////
//

// Package config 全局配置集
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/hjson/hjson-go"
)

// 基本配置常量。
const (
	ServerPort    = 7788 // 默认服务端口
	RemotePort    = 7788 // 远端目标端口
	MaxFindings   = 10   // 组网节点连接数
	PeersHelp     = 8    // 上线帮助发送条目数
	MaxApps       = 2000 // 每种应用默认的节点连接数上限（含depots）
	ListFindings  = 40   // 本类节点候选名单长度
	BufferSize    = 1024 // 连接读写缓冲区大小
	PeerFindRange = 300  // 节点寻找的范围（基于起点）
)

// 开发配置常量
// 部分值关系到安全性，不提供外部可配置。
const (
	SomeFindings  = 10                // 本类端组网发送条目数
	AppCleanLen   = 100               // 应用节点连接池单位清理长度（关联 MaxApps）
	FinderPatrol  = time.Minute * 10  // 本类节点连接切换巡查间隔
	BanExpired    = time.Hour * 4     // 恶意节点禁闭期限
	ClientPatrol  = time.Minute * 15  // 应用连接池巡查间隔（清除太老节点，节省内存）
	ClientExpired = time.Minute * 150 // 应用端在线最长时间（2.5h）
)

// 本服务规范名
const AppName = "findings"

// 日志文件名
const (
	LogsDirname  = "logs"         // 默认日志根目录
	LogFile      = "findings.log" // 主程序日志
	LogPeerFile  = "peers.log"    // 有效连接节点历史
	LogDebugFile = "debug.log"    // 调试日志
)

// 简单指令（无数据）
// 用文本形式有更好的可辨识性，避免简单数字可能的误撞。
const (
	CmdFindPing   = "Findings::Ping"   // 本网：可连接测试
	CmdFindOK     = "Findings::OK"     // 本网：服务确认（Findings），应答Ping
	CmdFindBye    = "Findings::ByeBye" // 本网：结束连接（友好）
	CmdFindHelp   = "Findings::Help"   // 本网：上线协助（初始获取服务器集。临时连接，无关连接池限制）
	CmdStunCone   = "__STUN__::Cone"   // STUN：请求NAT类型侦测主服务
	CmdStunSym    = "__STUN__::Sym"    // STUN：请求NAT类型侦测副服务
	CmdStunLive   = "__STUN__::Live"   // STUN：请求NAT存活期侦测服务
	CmdStunHost   = "__STUN__::Host"   // STUN：请求第三方主机发送一个UDP消息（NewHost）
	CmdStunHosted = "__STUN__::Hosted" // STUN：第三方主机发送UDP消息完成
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
	ServerPort    int    `json:"server_port"`           // 本地服务端口
	RemotePort    int    `json:"remote_port,omitempty"` // 远端节点服务端口（7788|443|0|...）
	LogDir        string `json:"log_dir"`               // 日志根目录
	Findings      int    `json:"findings"`              // 同时连接的本类节点数
	PeersHelp     int    `json:"peers_help"`            // 上线帮助发送条目数
	ConnApps      int    `json:"applications"`          // 可同时连接的应用端数量上限
	Shortlist     int    `json:"shortlist"`             // 本类节点候选名单长度
	BufferSize    int    `json:"buffer_size,omitempty"` // 连接读写缓冲区大小
	PeerFindRange int    `json:"peers_range"`           // 基于起点，节点寻找的范围
}

// Base 获取基础配置。
// 用户的配置文件为 ~/.findings/config.json
func Base() (*Config, error) {
	// 默认配置值
	config := Config{
		ServerPort:    ServerPort,
		RemotePort:    ServerPort,
		LogDir:        LogsDirname,
		Findings:      MaxFindings,
		PeersHelp:     PeersHelp,
		ConnApps:      MaxApps,
		Shortlist:     ListFindings,
		BufferSize:    BufferSize,
		PeerFindRange: PeerFindRange,
	}

	// 获取当前用户的家目录
	usr, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(usr, ".findings", "config.hjson")

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	err = hjson.Unmarshal(data, &config)
	return &config, err
}

// Peers 获取用户配置的节点IP信息集。
// 配置文件 ~/.findings/peers.json，内容可能由App发布时配置，或用户自己修改配置。
// 其中的IP应当至少是曾经有效的，其也可以作为 find.PointIPs 中的起点IP。
func Peers() ([]Peer, error) {
	var peers []Peer

	// 获取当前用户的家目录
	usr, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(usr, ".findings", "peers.json")

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return peers, err
	}

	err = json.Unmarshal(data, &peers)
	return peers, err
}

// Bans 获取用户配置的禁闭节点集（本网）。
// 配置文件 bans.json，存在于应用程序的安装目录之下。
// 注：
// 地址应当格式正确，无空格。
func Bans() (map[string]time.Time, error) {
	var bans []string

	usr, err := appDir()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(usr, ".config", "bans.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &bans)

	pool := make(map[string]time.Time)
	for _, v := range bans {
		pool[v] = time.Now()
	}

	return pool, err
}

// Services 读取服务配置集
// 服务器支持的应用类型名称，以及可受益的账户地址。
// 对于提供了服务但没有相应区块链收益地址的，账户设置为空串。
// 配置文件 ~/.findings/services.json
func Services() (map[string]string, error) {
	var stakes map[string]string

	// 获取当前用户的家目录
	usr, err := os.UserHomeDir()
	if err != nil {
		return stakes, err
	}
	configPath := filepath.Join(usr, ".findings", "services.json")

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return stakes, err
	}

	err = json.Unmarshal(data, &stakes)
	return stakes, err
}

// 获取应用程序当前目录。
func appDir() (string, error) {
	// 当前执行文件的路径
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}

	return filepath.Dir(exePath), nil
}
