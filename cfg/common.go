package cfg

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/hjson/hjson-go"
)

// Base 获取基础配置。
// 用户的配置文件为 ~/.findings/config.hjson
func Base() (*Config, error) {
	// 默认配置值
	config := &Config{
		UserID:      UserID,
		LogRoot:     "",
		ServerUport: ServerUport,
		ServerTport: ServerTport,
		RemoteUport: RemoteUport,
		RemoteTport: RemoteTport,
		Shortlist:   Shortlist,
		PunchXpool:  PunchXpool,
		ShareXpool:  ShareXpool,
		PeersHelp:   PeersHelp,
		PeersPunch:  PeersPunch,
		PeersRange:  PeersRange,
		STUNTest:    STUNTest,
		NATListen:   NATListen,
		NATLiving:   NATLiving,
		ClientOnly:  ClientOnly,
	}
	// 当前用户主目录
	usr, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(usr, fileDir, fileConfig)

	data, err := os.ReadFile(configPath)
	// 容错文件不存在
	if err != nil {
		log.Println("[Error]", err)
		return config, nil
	}
	err = hjson.Unmarshal(data, config)

	return config, err
}

// Peers 获取用户配置的节点IP信息集。
// 配置文件 ~/.findings/peers.json，内容可能由App发布时配置，或用户自己修改配置。
// 其中的IP应当至少是曾经有效的，其也可以作为 find.PointIPs 中的起点IP。
// 返回的集合中排除了重复的IP地址。
func Peers() (map[netip.Addr]*Peer, error) {
	var peers []*Peer

	// 当前用户主目录
	usr, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	list := make(map[netip.Addr]*Peer)
	configPath := filepath.Join(usr, fileDir, filePeers)

	data, err := os.ReadFile(configPath)
	// 容错文件不存在
	if err != nil {
		log.Println("[Error]", err)
		return list, nil
	}
	// 解码JSON
	if err = json.Unmarshal(data, &peers); err != nil {
		return nil, err
	}
	// 剔除重复IP
	for _, peer := range peers {
		list[peer.IP] = peer
	}
	return list, nil
}

// Bans 获取用户配置的禁闭节点集。
// 配置文件 bans.json，存在于应用程序的系统缓存目录下。
// 注：
// 地址应当格式正确，无空格。
func Bans() (map[string]time.Time, error) {
	var bans []string

	usr, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	pool := make(map[string]time.Time)
	configPath := filepath.Join(usr, fileBans)

	data, err := os.ReadFile(configPath)
	// 容错文件不存在
	if err != nil {
		log.Println("[Error]", err)
		return pool, nil
	}
	// 存在即需格式正确
	if err = json.Unmarshal(data, &bans); err != nil {
		return nil, err
	}
	for _, k := range bans {
		pool[k] = time.Now()
	}
	return pool, nil
}

// Stakes 读取权益配置集
// 服务器支持的应用类型名称，以及可受益的账户地址。
// 对于提供了服务但没有相应区块链收益地址的，账户设置为空串。
// 配置文件 ~/.findings/stakes.hjson
func Stakes() (map[string]string, error) {
	// 用户主目录
	usr, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	var stakes map[string]string
	configPath := filepath.Join(usr, fileDir, fileStakes)

	data, err := os.ReadFile(configPath)
	// 容错文件不存在
	if err != nil {
		log.Println("[Error]", err)
		return stakes, nil
	}
	err = hjson.Unmarshal(data, &stakes)

	return stakes, err
}

// CreateLoger 创建一个日志记录器。
// 返回的 os.File 用于外部执行关闭清理操作。
// @path 存储路径，可选
// @filename 日志文件名
// @prefix 日志前缀字符串
func CreateLoger(path, filename, prefix string) (*log.Logger, *os.File, error) {
	if path == "" {
		return nil, nil, fmt.Errorf("logs path is empty")
	}
	fpath := filepath.Join(path, filename)

	logFile, err := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, err
	}
	return log.New(logFile, prefix, log.Ldate|log.Ltime|log.Lshortfile), logFile, nil
}
