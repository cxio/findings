package conf

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
)

// Peer 已知的确定端点。
type Peer struct {
	IP   net.IP `json:"ip"`             // 监听IP
	Port uint16 `json:"port,omitempty"` // 监听端口
}

// Config 配置集。
// 成员数据可以被修改，用于配置传递。
type Config struct {
	AppName  string            // 程序名
	ServIP   net.IP            // 服务监听IP
	Port     int               // 监听端口
	Logdir   string            // 日志根目录（全路径）
	Peers    []Peer            // 配置的已知端点集
	Stakes   map[string]string // 权益地址集
	Siblings int               // 同时连接的兄弟端点数
	Clients  int               // 同时连接的客户端点数
	Conveys  int               // 同时连接的传送器数
	Manages  int               // 同时连接的管理端点数
}

//
// New 创建一个默认配置对象。
//
func New() *Config {
	return &Config{
		AppName:  "findings",
		Port:     ServPort,
		Logdir:   filepath.Join(homeDir, LogsDirname),
		Peers:    make([]Peer, 0),
		Stakes:   make(map[string]string),
		Siblings: MaxSibling,
		Clients:  MaxClient,
		Conveys:  MaxConvey,
		Manages:  MaxManage,
	}
}

//
// Default 默认全景配置实例。
//
var Default = New()

//
// Load 载入外部配置的内容（JSON）。
//
func (cfg *Config) Load(r io.Reader) error {
	code, err := ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("%s %s", errConfig, err)
	}
	var cj configJSON

	if err = json.Unmarshal(code, &cj); err != nil {
		return fmt.Errorf("%s %s", errJSON, err)
	}
	pickConfig(cfg, &cj)
	defaultPort(cfg)

	return nil
}

//
// Puts 输出配置到外部存储（JSON）。
// @nice 对JSON格式进行外观友好格式化。
//
func (cfg *Config) Puts(w io.Writer, nice bool) error {
	b, err := putJSON(cfg, nice)

	if err != nil {
		_, err = w.Write(b)
	}
	return err
}

//
// LogFile 获取日志全路径文件名。
// 传递的文件名参数可为：
// 	- LogFile 普通日志
// 	- LogPeerFile 端点专项日志
// 	- LogDebugFile 调试信息日志
//
func (cfg *Config) LogFile(fname string) string {
	return filepath.Join(cfg.Logdir, fname)
}

//
// 外部可配置的条目集。
//
type configJSON struct {
	AppName string            `json:"appname"`
	ServIP  net.IP            `json:"servip,omitempty"`
	Port    int               `json:"port,omitempty"`
	Logdir  string            `json:"logdir,omitempty"`
	Peers   []Peer            `json:"peers,omitempty"`
	Stakes  map[string]string `json:"stakes"`
}

//
// 提取外部配置。
//
func pickConfig(c *Config, cj *configJSON) {
	if cj.ServIP != nil {
		c.ServIP = cj.ServIP
	}
	if cj.Port != 0 {
		c.Port = cj.Port
	}
	if cj.Peers != nil {
		c.Peers = cj.Peers
	}
	if cj.Stakes != nil {
		c.Stakes = cj.Stakes
	}
	if cj.Logdir != "" {
		c.Logdir = filepath.Join(homeDir, cj.Logdir)
	}
}

//
// 设置默认端口（如果外部没有设置的话）。
// 在提取外部配置之后调用。
//
func defaultPort(cfg *Config) {
	if cfg.Port == 0 {
		cfg.Port = ServPort
	}
	for _, p := range cfg.Peers {
		if p.Port == 0 {
			p.Port = ServPort
		}
	}
}

//
// 转为数据到JSON格式。
//
func putJSON(v interface{}, nice bool) ([]byte, error) {
	var b []byte
	var err error

	if nice {
		b, err = json.MarshalIndent(v, "", "\t")
	} else {
		b, err = json.Marshal(v)
	}
	if err != nil {
		err = fmt.Errorf("%s %s", errJSON, err)
	}
	return b, err
}

// RngNode 范围节点定义。
type RngNode struct {
	IP    net.IP `json:"ip"`    // 网段IP
	Begin int    `json:"begin"` // 起始主机号
	End   int    `json:"end"`   // 主机号终点（不含）
	Ports [2]int `json:"port"`  // [min, max]，max小于min时视为min单个端口
}

// RngNodes 节点集序列。
type RngNodes []RngNode

//
// Load 载入节点配置。
//
func (rns *RngNodes) Load(r io.Reader) error {
	code, err := ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("%s %s", errConfig, err)
	}
	if err = json.Unmarshal(code, rns); err != nil {
		return fmt.Errorf("%s %s", errJSON, err)
	}
	return nil
}

//
// Puts 输出配置到外部存储。
// @nice 对JSON格式进行外观友好格式化。
//
func (rns *RngNodes) Puts(w io.Writer, nice bool) error {
	b, err := putJSON(rns, nice)

	if err != nil {
		_, err = w.Write(b)
	}
	return err
}

//
// 共享消息文本。
//
const (
	errConfig = "load config failed: "
	errJSON   = "JSON unmarshaling failed: "
)
