// Package conf 程序全局配置
// 包含编译期的固定配置，
// 外部通过JSON指定的运行期的配置。
//
package conf

import (
	"path/filepath"
	"time"

	"github.com/cxio/cxsuite/bcutil"
)

// 基本配置常量。
const (
	ServPort   = 20170          // 默认服务端口
	ManagePort = 20169          // 管理服务端口
	MaxSibling = 8              // 同时连接最多兄弟端点数
	MaxClient  = 20             // 同时连接最多客户端点数
	MaxConvey  = 10             // 同时连接最多传送器端点数
	MaxManage  = 3              // 同时连接最多管理端点数
	BanLasting = time.Hour * 24 // 恶意端点禁闭期
)

const appName = "findings"

// 日志文件名，
// 相对于日志根目录。
const (
	LogsDirname  = "logs" // 默认日志根目录名
	LogFile      = "finding.log"
	LogPeerFile  = "peers.log"
	LogDebugFile = "debug.log"
)

var (
	// 程序数据主目录
	homeDir = bcutil.AppDataDir(appName, false)
)

// 计算后文件路径。
// 包级不变的变量，外部不应修改它们。
var (
	// 配置文件
	ConfigFile = filepath.Join(homeDir, "config.json")
	NodesFile  = filepath.Join(homeDir, "nodes.json")
	WalletFile = filepath.Join(homeDir, "wallet.json")

	// 数据文件
	PeersFile   = filepath.Join(homeDir, "peers.dat")
	BansFile    = filepath.Join(homeDir, "bans.dat")
	RPCKeyFile  = filepath.Join(homeDir, "rpc.key")
	RPCCertFile = filepath.Join(homeDir, "rpc.cert")

	// 临时存储空间
	// 当软件重启时保留端点信息缓存。
	TempDir = filepath.Join(homeDir, "tmp")
)

// 兄弟端点最大连接数。
const findingConnMax = 16
