package node

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cxio/findings/base"
	"github.com/cxio/findings/config"
	"github.com/cxio/findings/node/pool"
	"github.com/cxio/findings/stun"
	"github.com/gorilla/websocket"
	"golang.org/x/exp/constraints"
)

// 关联节点引用（UDP打洞）
type LinkPeer = stun.Peer

// 并发清理并发量
const cleanNCount = 10

// 客户端UDP处理器映射
var clientsUDP = NewClientApps()

//
// 应用支持
//////////////////////////////////////////////////////////////////////////////

// Applier 应用端服务员
// 与 Finder 字段完全相同，但两者所支持的方法集不同。
type Applier struct {
	*Node                     // 对端节点
	*LinkPeer                 // 打洞关联节点
	Kind      string          // 应用类别名
	Conn      *websocket.Conn // 当前连接（TCP）
	done      chan struct{}   // 服务结束通知
}

// NewApplier 创建一个应用端服务员
// 初始构建时不设置打洞关联节点（LinkPeer）。
func NewApplier(node *Node, kname string, conn *websocket.Conn) *Applier {
	return &Applier{
		Node:     node,
		LinkPeer: nil,
		Kind:     kname,
		Conn:     conn,
		done:     make(chan struct{}),
	}
}

// SetLinkPer 设置关联节点
func (a *Applier) SetLinkPer(peer *LinkPeer) {
	a.LinkPeer = peer
}

// Server 作为服务器启动。
// 对传入的各种类型应用的打洞请求进行回应。
// 注记：
// 应用服务员只有服务进程，无对外连出。
func (a *Applier) Server(ctx context.Context, notice chan<- *stun.Notice, client <-chan *stun.Client) {
	log.Printf("A applier serve start [%s]\n", a.Node)
	start := time.Now()
top:
	for {
		select {
		case <-ctx.Done():
			break top

		case <-a.done:
			break top

		// 对端UDP节点信息处理
		case cli := <-client:
			//1. 通过TCP链路告知其公网地址
			app := clientsUDP.Get(cli.SN)
			if app == nil {
				log.Println("[Warning] the UDP Applier not found.")
				break
			}
			// 注意：由匹配的Applier发送
			if err := app.SendPeerUDP(cli.Addr); err != nil {
				log.Println("[Error]", err)
			}
			//2. 本地UDP发送 Listen, NewPort
			notice <- stun.NewNotice(stun.UDPSEND_LOCAL, cli.Addr, cli.SN)
			notice <- stun.NewNotice(stun.UDPSEND_NEWPORT, cli.Addr, cli.SN)

			//3. 由组网池随机节点请求NewHost协作
			max := min(findings.Size(), xhostCount)
			if max <= 0 {
				log.Println("[Error]", ErrEmptyPool)
				break
			}
			for _, finder := range findings.List(max) {
				finder.NewHost(cli)
			}
			// 已无需求，可清理
			clientsUDP.Remove(cli.SN)

		default:
			typ, msg, err := a.Conn.ReadMessage()
			if err != nil {
				log.Println("[Error] read message failed on", err)
				break top
			}
			switch typ {
			// 简单指令
			case websocket.TextMessage:
				if err := a.simpleProcess(string(msg), a.Conn); err != nil {
					log.Println(err)
					break top
				}
			// 复合指令
			case websocket.BinaryMessage:
				if err := a.process(msg, a.Conn); err != nil {
					log.Printf("[%s] finder service exited on %s\n", a.Node, err)
					break top
				}
			}
		}
	}
	// 结束：移出应用池
	if a.LinkPeer != nil {
		pool, err := applPools.Appliers(a.Kind, a.Level)
		if err != nil {
			log.Println("[Error]", err)
			return
		}
		its := pool.Dispose(a.Conn)
		if its != nil {
			its.Quit()
		}
	}
	log.Printf("[%s] applier served for %s\n", a.Node, time.Since(start))
}

// 服务：单次读取处理。
// 包含NAT类型探测服务和UDP打洞信令协助。
// 注记：
// 仅在需要退出服务时才返回错误。
func (a *Applier) process(data []byte, conn *websocket.Conn) error {
	// 顶层解码
	cmd, data, err := base.DecodeProto(data)
	if err != nil {
		return err
	}
	switch cmd {
	// 查询应用类型支持
	// data: string
	case base.COMMAND_APPKIND:
		msg := base.CmdKindFail

		if applPools.Supported(string(data)) {
			msg = base.CmdKindOK
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			return err
		}

	// 执行UDP打洞协助
	case base.COMMAND_STUN:
		kind, punch, err := stun.DecodePunch(data)
		if err != nil {
			return err
		}
		if !applPools.Supported(kind) {
			return ErrAppKind
		}
		if err = servicePunching(conn, punch, applPools.Appliers4(kind), cfgUser.STUNPeerAmount); err != nil {
			log.Println("stun server failed of", err)
		}

	// 消息不合规
	default:
		return ErrSendIllegal
	}
	return nil // 上级正常迭代
}

// 服务：单次简单处理。
// 当对端发送简单的文本消息时，根据消息值的不同作相应处理。
// 主要是响应对端的NAT层级和生存期探测请求。
// 注意：
// STUN:Cone 和 STUN:Sym 处理的连接（conn）并不是同一个客户端。
// 这两者是离散的：只要检测到其请求，即可提供服务。
func (a *Applier) simpleProcess(msg string, conn *websocket.Conn) error {
	switch msg {
	// 请求TCP直连节点
	case base.CmdAppsTCP:
		return a.sendPeersTCP(conn, config.AppServerTCP)

	// STUN:Cone 主服务
	case base.CmdStunCone:
		return a.sendServInfo(conn, cfgUser.UDPListen, base.COMMAND_STUN_CONE, clientsUDP)

	// STUN:Sym 副服务
	case base.CmdStunSym:
		return a.sendServInfo(conn, cfgUser.UDPListen, base.COMMAND_STUN_SYM, clientsUDP)

	// STUN:Live NAT存活期探测
	case base.CmdStunLive:
		return a.sendServInfo(conn, cfgUser.UDPLiving, base.COMMAND_STUN_LIVE, clientsUDP)

	// 连接内对端查询
	case base.CmdFindPing:
		return conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindOK))

	// 结束连接
	case base.CmdFindBye:
		return ErrServiceDone
	}

	// 消息不合规时抵达这里
	return ErrSendIllegal
}

// 向对端发送服务器UDP信息（stun.ServInfo）。
// 当客户端向服务器请求 STUN:Cone|Sym|Live 服务时发生。
// 对于客户端来说，STUN 的这三个服务虽然有其内在逻辑顺序，但在服务器中它们是独立的，
// 因为客户端通常向不同的服务器请求不同的服务。
// 注意：
// 客户端需要使用与TCP链路相同的源IP来发送UDP消息，这通常不是问题。
// @conn 当前TCP连接
// @port UDP监听端口（NAT探测或Live）
// @cmd 数据类型指令
// @cache 客户端=>Applier映射集
func (a *Applier) sendServInfo(conn *websocket.Conn, port int, cmd base.Command, cache *clientApps) error {
	// 约束：TCP, UDP 同IP
	ip, _ := stun.AddrPort(conn.RemoteAddr())

	// 序列号与对端IP相关联
	sn, rnd16, err := stun.GenerateClientSN(base.GlobalSeed, ip)
	if err != nil {
		return err
	}
	// 对称密钥
	key := stun.GenerateSnKey(base.GlobalSeed, rnd16)

	// 服务端信息
	data, err := stun.EncodeServInfo(port, sn[:], key[:], rnd16[:])
	if err != nil {
		return err
	}
	// 封装编码
	data, err = base.EncodeProto(cmd, data)
	if err != nil {
		return err
	}
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return err
	}

	cache.Add(sn, a) // 将自己添加到映射表
	return nil
}

// 向对端发送TCP服务器节点信息。
// @conn 目标连接
// @count 发送数量
func (a *Applier) sendPeersTCP(conn *websocket.Conn, count int) error {
	store, err := tcpStores.TCPStore(a.Kind)
	if err != nil {
		return err
	}
	list := store.List(count)

	if list == nil {
		return ErrEmptyPool
	}
	return findingsPush(conn, list, base.COMMAND_PEERSTCP)
}

// SendPeerUDP 向客户端发送其节点UDP信息。
// @addr 客户端的UDP地址
func (a *Applier) SendPeerUDP(addr *net.UDPAddr) error {
	data, err := stun.EncodeUDPInfo(addr)
	if err != nil {
		return err
	}
	data, err = base.EncodeProto(base.COMMAND_STUN_PEER, data)
	if err != nil {
		return err
	}
	if err = a.Conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return err
	}
	return nil
}

// String 服务员的字符串表示（对端信息）
// 格式：IP:Port(Level)
func (a *Applier) String() string {
	return fmt.Sprintf("%s(%d)", a.Node.String(), a.Level)
}

// Quit 节点退出。
func (a *Applier) Quit() {
	close(a.done)
}

// Appliers 应用端服务员缓存池。
type Appliers struct {
	pool pool.Pool[Applier]
}

// Applier 到期测试
// 下线或者存活时间过期。下线测试可能会需要较长时间。
// @long 存活期时长
func expireApplier(a *Applier, long time.Duration) bool {
	return time.Now().Before(a.Start.Add(long)) || offline(a.Conn, -1)
}

// NewAppliers 创建集合。
// size 可以为零或负数，这样就不会创建实例。
// 比如当前服务器不提供对外应用端服务（NAT 内网 Finder）。
// @size 池大小限制
// @cleanlen 清理的片段长度。
// @net 支持的网络类型（tcp|udp）
func NewAppliers(size int) *Appliers {
	if size <= 0 {
		return nil
	}
	return &Appliers{
		pool: *pool.NewPool[Applier](size),
	}
}

// Add 添加成员到缓存池。
func (a *Appliers) Add(node *Applier) error {
	return pool.Add(&a.pool, node)
}

// Dispose 清除目标连接节点。
// @conn 目标连接
// @return 被移除的目标节点
func (a *Appliers) Dispose(conn *websocket.Conn) *Applier {
	test := func(node *Applier) bool {
		return conn == node.Conn
	}
	return pool.Dispose(&a.pool, test)
}

// Get 引用一个随机成员。
// @return1 目标成员的位置下标
// @return2 目标成员
func (a *Appliers) Get() *Applier {
	return pool.Get(&a.pool)
}

// List 获取指定数量的随机成员。
// 如果指定的长度为负值或超过了池内节点数，返回全部节点。
// 返回集成员已随机化。
// @count 获取的成员数量
// @return 一个随机成员序列
func (a *Appliers) List(count int) []*Applier {
	return pool.List(&a.pool, count)
}

// Clean 清理缓存池
// 移除入池时间太久或已经下线的成员。
// 应用池较大，因此采用并发的清理方式（pool.CleanN）。
// @long 指定过期时间长度
func (a *Appliers) Clean(ctx context.Context, long time.Duration) {
	test := func(a *Applier) bool {
		return expireApplier(a, long)
	}
	start := time.Now()
	cnt := 0
	out := pool.CleanN(ctx, &a.pool, cleanNCount, test)

	for its := range out {
		its.Quit()
		cnt++
	}
	log.Printf("Cleaning %d appliers took %s\n", cnt, time.Since(start))
}

// Size 返回缓存池大小
func (a *Appliers) Size() int {
	return pool.Size(&a.pool)
}

// IsFulled 缓存池是否满员
func (a *Appliers) IsFulled() bool {
	return pool.IsFulled(&a.pool)
}

// 按NAT分类的应用服务员池组
// [0] - Pub&FullC
// [1] - RC
// [2] - P-RC
// [3] - Sym
type appliers4 [4]*Appliers

func newAppliers4(size int) appliers4 {
	var app4 [4]*Appliers

	for i := 0; i < 4; i++ {
		app4[i] = NewAppliers(size)
	}
	return app4
}

// AppliersPool 应用服务员池组集
// 包含任意应用类型，每一个类型对应一个按NAT分类的双协议池组。
// key: 应用类型名（kind:name）
type AppliersPool map[string]appliers4

// NewClientsPool 创建一个应用服务员池组集
func NewAppliersPool() AppliersPool {
	return make(map[string]appliers4)
}

// Init 初始化应用池组。
// 每一种应用初始使用时都需要调用该初始化函数。
// 注意：
// 不支持并发安全，因此用户需要在程序最开始时初始化自己支持的所有应用。
// @kind 应用类型名（kind:name）
// @size 池大小限制
func (cp AppliersPool) Init(kind string, size int) {
	cp[kind] = newAppliers4(size)
}

// Appliers 获取一个应用服务员集。
// level:
// - NAT_LEVEL_NULL
// - NAT_LEVEL_RC
// - NAT_LEVEL_PRC
// - NAT_LEVEL_SYM
//
// @kind 应用类型名（kind:name）
// @level 目标NAT层级（0 ~ 3）
// @return 目标类型的节点池
func (cp AppliersPool) Appliers(kind string, level NatLevel) (*Appliers, error) {
	p4, ok := cp[kind]
	if !ok {
		return nil, ErrAppKind
	}
	return p4[level], nil
}

// AppliersUDP 提取目标类型的UDP打洞信息组
// 如果不支持目标类型，返回nil。
// 注：
// Sym 在 Pub/FullC 主动请求时有用，但单向连接无需打洞。
func (cp AppliersPool) Appliers4(kind string) []*Appliers {
	if p4, ok := cp[kind]; ok {
		return p4[:]
	}
	log.Printf("The kind of [%s] not supported.\n", kind)
	return nil
}

// Supported 是否支持目标类型服务。
func (cp AppliersPool) Supported(kind string) bool {
	if _, ok := cp[kind]; ok {
		return true
	}
	return false
}

// Clean 清理目标类型的应用池组
// @kinds 应用名称集（kind:name）
// @long 有效期时长
func (cp AppliersPool) Clean(ctx context.Context, kinds []string, long time.Duration) {
	for _, kind := range kinds {
		p4, ok := cp[kind]
		if !ok {
			continue
		}
		for _, pool := range p4 {
			go pool.Clean(ctx, long)
		}
	}
}

// Size 获取应用池集大小。
// 即池集支持的应用类型多少。
func (cp AppliersPool) Size() int {
	return len(cp)
}

//
// 工具函数
//////////////////////////////////////////////////////////////////////////////

// Online 检查对端是否在线
// 向目标连接发送探测消息，检查对端是否回应。
// 因为是在已有的连接上测试，所以对端无论返回啥消息，都表示在线。
// @conn 当前连接
// @long 读取等待超时，负值或零表示采用默认值
// @return 非nil表示下线
func Online(conn *websocket.Conn, long time.Duration) error {
	// Ping
	err := conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindPing))
	if err != nil {
		return err
	}
	if long <= 0 {
		long = defaultTimeout
	}
	conn.SetReadDeadline(time.Now().Add(long))
	_, _, err = conn.ReadMessage()

	return err
}

// 下线判断。
// 向目标连接发送探测消息，检查对端是否正常回应。
// @conn 当前连接
// @long 读取等待时间
// @return 下线返回true，反之为false
func offline(conn *websocket.Conn, long time.Duration) bool {
	if err := Online(conn, long); err != nil {
		log.Println("node is unreachable on", err)
		return true
	}
	return false
}

// 通用取小值
func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}
