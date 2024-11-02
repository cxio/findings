package node

import (
	"errors"
	"log"
	"sync"

	"github.com/cxio/findings/base"
	"github.com/cxio/findings/config"
	"github.com/cxio/findings/stun"
	"github.com/gorilla/websocket"
	"golang.org/x/exp/rand"
)

// NAT 层级
type NatLevel = stun.NatLevel

// 序列号引用
type ClientSN = stun.ClientSN

var (
	// 应用端节点池组为空
	ErrAppsEmpty = errors.New("the clients pools is empty")

	// 没有匹配的打洞节点
	ErrAppNotFound = errors.New("no matching nodes on STUN service")
)

// 局部需用常量引用。
// 注：主要用于 appliers4 类型取成员值。
const (
	NAT_LEVEL_NULL   = stun.NAT_LEVEL_NULL
	NAT_LEVEL_RC     = stun.NAT_LEVEL_RC
	NAT_LEVEL_PRC    = stun.NAT_LEVEL_PRC
	NAT_LEVEL_SYM    = stun.NAT_LEVEL_SYM
	NAT_LEVEL_PRCSYM = stun.NAT_LEVEL_PRCSYM
	NAT_LEVEL_ERROR  = stun.NAT_LEVEL_ERROR
)

// NatNames NAT 类型名集
var NatNames = []string{
	NAT_LEVEL_NULL:   "Pub/FullC", // 0: Public | Public@UPnP | Full Cone
	NAT_LEVEL_RC:     "RC",        // 1: Restricted Cone (RC)
	NAT_LEVEL_PRC:    "P-RC",      // 2: Port Restricted Cone (P-RC)
	NAT_LEVEL_SYM:    "Sym",       // 3: Symmetric NAT (Sym) | Sym UDP Firewall
	NAT_LEVEL_PRCSYM: "P-RC|Sym",  // 4: P-RC | Sym
	NAT_LEVEL_ERROR:  "Unknown",   // 5: UDP链路不可用，或探测错误默认值
}

// 请求NewHost协作的节点数
// 该协作没有确定性回馈，因此执行冗余请求。
// 注记：
// 如果用户没有得到满足，他可以再次请求NAT探测。
// 相比于网络节点间确定性同步，这个策略要简单实用得多。
const xhostCount = 2

// 客户端服务员映射。
// 用于客户端的TCP链路的Applier服务员和UDP链路的对应。
// 即：UDP发送的信息，应当由TCP上相应的服务员处理。
// 注记：
// 不用netip.Addr来作为键，因为同一个客户端可能运行多个实例。
type clientApps struct {
	cache map[ClientSN]*Applier
	mu    sync.Mutex
}

// NewClientApps 新建一个映射表。
func NewClientApps() *clientApps {
	return &clientApps{
		cache: make(map[ClientSN]*Applier),
	}
}

// Add 添加一个映射。
func (cc *clientApps) Add(sn ClientSN, conn *Applier) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.cache[sn] = conn
}

// Remove 移除一个映射
func (cc *clientApps) Remove(sn ClientSN) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	delete(cc.cache, sn)
}

// Get 获取序列号对应的客户端连接
// 返回nil表示未找到目标。
func (cc *clientApps) Get(sn ClientSN) *Applier {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return cc.cache[sn]
}

// 服务辅助
//////////////////////////////////////////////////////////////////////////////

// 打洞协助（多目标）
// 随机提取相应类型的应用节点，向双方发送彼此的节点信息。
// 随机提取可能重复，因此amount只是数量上限，而非必须满足的值。
// 逐个提取和发送，因此对端需要逐个提取。
// 注记：
// 重复越多，说明池中节点量越少，满足固定的数量会是一个问题。
//
// @conn 请求源客户端连接
// @punch 源客户端打洞信息包
// @pools NAT 节点池组（0:Pub/FullC; 1:RC; 2:P-RC; 3:Sym）
// @amount 尝试协助互通的节点数上限
func servicePunching(conn *websocket.Conn, punch *LinkPeer, pools []*Appliers, amount int) error {
	if pools == nil {
		return ErrAppsEmpty
	}
	// 随机匹配
	// 可能重复，因此标记
	pass := make(map[*websocket.Conn]bool)

	for n := 0; n < amount; n++ {
		client, err := punchingPeer(conn, punch, pools, config.STUNTryMax)

		// 条件不具备，无需再尝试
		if err != nil {
			return err
		}
		// 简单略过，计量继续
		if pass[client.Conn] {
			continue
		}
		pass[client.Conn] = true
	}
	return nil
}

// 应用端打洞协助（单次）
// 参考对端的NAT类型，匹配恰当的互连节点，为它们提供信令服务：
// 向彼此写入对端的信息（同时指明打洞方向）。
// @conn 请求源客户端连接
// @punch 源客户端打洞信息包
// @pools NAT 节点池组（0:Pub/FullC; 1:RC; 2:P-RC; 3:Sym）
// @max 失败再尝试次数
// @return 成功写入打洞信息包的匹配端
func punchingPeer(conn *websocket.Conn, punch *LinkPeer, pools []*Appliers, max int) (*Applier, error) {
	var err error
	var dir *stun.PunchDir
	var peer *Applier

	for n := 0; n < max; n++ {
		peer = punchMatched(punch.Level, pools)

		if peer == nil {
			return nil, ErrAppNotFound
		}
		punch2 := peer.LinkPeer

		// dir[0] punch
		// dir[1] punch2
		if dir, err = stun.PunchingDir(punch, punch2); err != nil {
			return nil, err
		}
		// 向匹配端写入
		// 成功即退出，否则尝试新的匹配。
		if err = punchingPush(peer.Conn, dir[1], punch2, base.COMMAND_PUNCH); err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	// 向请求源写入
	return peer, punchingPush(conn, dir[0], punch, base.COMMAND_PUNCH)
}

// 向应用端连接写入打洞信息包
// 信息包依然为两级封装，内层编码需用 stun.DecodePunch 解码。
// @conn 应用端连接
// @punch 打洞信息包
// @cmd 顶层封装类别（应为 COMMAND_PUNCH）
// @return 返回错误通常表示传输失败（对端不在线）
func punchingPush(conn *websocket.Conn, dir string, punch *LinkPeer, cmd base.Command) error {
	// 内层编码
	data, err := stun.EncodePunch(dir, punch)
	if err != nil {
		return err
	}
	// 顶层编码
	data, err = base.EncodeProto(cmd, data)
	if err != nil {
		return err
	}
	// 传送到对端
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		log.Println("[Error] send punch's data.")
	}
	return err
}

// 工具函数
//////////////////////////////////////////////////////////////////////////////

// 获取一个打洞匹配节点
// 传递一方的NAT层级为level，找到与之匹配的另一个节点。
// 匹配遵循资源充分利用原则：
// level:
// - Sym:       Pub/FullC
// - P-RC:      RC > P-RC > Pub/FullC
// - RC:        P-RC > RC > Pub/FullC
// - Pub/FullC: Sym > P-RC > RC > Pub/FullC
// pools:
// - [0]: Pub/FullC
// - [1]: RC
// - [2]: P-RC
// - [3]: Sym
// 注：
// 返回nil表示没有匹配的节点，通常是因为应用端节点池为空所致。
func punchMatched(level stun.NatLevel, pools []*Appliers) *Applier {
	// Pub/FullC
	c0 := pools[0].Get()

	if level == stun.NAT_LEVEL_SYM {
		return c0
	}
	c1 := pools[1].Get() // RC
	c2 := pools[2].Get() // P-RC
	c3 := pools[3].Get() // Sym

	switch level {
	case NAT_LEVEL_PRC:
		return increaseRandomNode(c0, c2, c1)
	case NAT_LEVEL_RC:
		return increaseRandomNode(c0, c1, c2)
	case NAT_LEVEL_NULL:
		return increaseRandomNode(c0, c1, c2, c3)
	}
	return nil
}

// 递增法随机节点获取
// 权重值按参数顺序递增，从1开始。
// 池中添加实参成员，随着权重增加，重复添加（增加高权重项的数量）。
// 最终取一个随机位置值。
func increaseRandomNode(cs ...*Applier) *Applier {
	size := increaseSum(1, 1, len(cs))
	pool := make([]*Applier, 0, size)

	for i, its := range cs {
		if its != nil {
			// 重复量逐渐增加
			for n := 0; n < i+1; n++ {
				pool = append(pool, its)
			}
		}
	}
	size = len(pool)
	if size == 0 {
		return nil
	}
	// 随机数列的随机位置
	// i: [random...][rand-id]
	return pool[rand.Perm(size)[rand.Intn(size)]]
}

// 递增等差数列求和
// @a 起始值
// @d 等差值
// @n 项数
// @return 求和值
func increaseSum(a, d, n int) int {
	return n * (2*a + (n-1)*d) / 2
}
