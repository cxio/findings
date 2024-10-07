// 节点模块
// 包含Findings候选池、连接池以及应用节点池的支持。
package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/cxio/findings/base"
	"github.com/cxio/findings/pool"
	"github.com/cxio/findings/stun"
	"github.com/gorilla/websocket"
)

// NAT 层级
type NatLevel = stun.NatLevel

// 关联节点引用
type LinkPeer = stun.LinkPeer

// 序列号引用
type ClientSN = stun.ClientSN

var (
	// 在线测试错误
	ErrOnline = errors.New("the target node is offline")

	// 不支持目标类型应用
	ErrAppKind = errors.New("not support the kind of application")

	// 无效的NAT层级（TCP不支持）
	ErrNatLevel = errors.New("NAT Level is invalid")

	// 无效的网络协议名
	ErrNetwork = errors.New("the network is invalid")

	// NewHost 协助错误
	ErrNewHost = errors.New("the new-host request failed")
)

// 局部需用常量引用。
// 注：主要用于 appliers4 类型取成员值。
const (
	NAT_LEVEL_NULL = stun.NAT_LEVEL_NULL
	NAT_LEVEL_RC   = stun.NAT_LEVEL_RC
	NAT_LEVEL_PRC  = stun.NAT_LEVEL_PRC
	NAT_LEVEL_SYM  = stun.NAT_LEVEL_SYM
)

// NatNames NAT 类型名集
var NatNames = []string{
	NAT_LEVEL_NULL:        "Pub/FullC", // 0: Public | Public@UPnP | Full Cone
	NAT_LEVEL_RC:          "RC",        // 1: Restricted Cone (RC)
	NAT_LEVEL_PRC:         "P-RC",      // 2: Port Restricted Cone (P-RC)
	NAT_LEVEL_SYM:         "Sym",       // 3: Symmetric NAT (Sym) | Sym UDP Firewall
	stun.NAT_LEVEL_PRCSYM: "P-RC|Sym",  // 4: P-RC | Sym
	stun.NAT_LEVEL_ERROR:  "Unknown",   // 5: UDP链路不可用，或探测错误默认值
}

const (
	cleanNCount    = 10               // 并发清理并发量
	defaultTimeout = time.Second * 30 // 默认超时时间
)

//
// 通用节点
//////////////////////////////////////////////////////////////////////////////

// Node 在线节点
// 在线节点信息，用于等待创建连接的备用（候选池）。
type Node struct {
	IP    netip.Addr    // 对端 IP
	Port  int           // 监听/通讯端口
	Start time.Time     // 连接开始时间
	Ping  time.Duration // 节点距离（抵达时长）
}

// New 创建一个节点
// @ip 节点公网IP地址
// @port 节点对外端口
func New(ip netip.Addr, port int) *Node {
	return &Node{
		IP:    ip,
		Port:  port,
		Start: time.Now(),
	}
}

// NewWithAddr 从net.Addr实参创建节点
func NewWithAddr(addr net.Addr) *Node {
	var ap netip.AddrPort

	switch x := addr.(type) {
	case *net.TCPAddr:
		ap = x.AddrPort()
	case *net.UDPAddr:
		ap = x.AddrPort()
	default:
		return nil
	}
	return &Node{IP: ap.Addr(), Port: int(ap.Port()), Start: time.Now()}
}

// NewFromPeer 从传输数据Peer构造。
// 解析错误返回nil（忽略、容错），避免恶意破坏。
func NewFromPeer(p *Peer) *Node {
	ip, ok := netip.AddrFromSlice(p.Ip)
	if !ok {
		log.Println("Error from parse Peer's ip:", p)
		return nil
	}
	return &Node{IP: ip, Port: int(p.Port), Start: time.Now()}
}

// String 字符串表示
// 格式：IP:Port
// 安全：不提供时间状态，隐私安全考虑。
func (n *Node) String() string {
	return netip.AddrPortFrom(n.IP, uint16(n.Port)).String()
}

//
// 候选池
//////////////////////////////////////////////////////////////////////////////

// Shortlist 候选池类型。
type Shortlist struct {
	pool pool.Pool[Node]
}

// NewShortlist 创建一个新的候选池。
func NewShortlist(size int) *Shortlist {
	if size <= 0 {
		return nil
	}
	return &Shortlist{
		pool: *pool.NewPool[Node](size),
	}
}

// Add 添加一个候选节点。
// @node 待添加入池的节点
func (s *Shortlist) Add(node *Node) error {
	return pool.Add(&s.pool, node)
}

// Adds 添加多个候选节点。
// @list 待添加的节点序列
// @return 实际成功添加的数量
func (s *Shortlist) Adds(list ...*Node) int {
	return pool.Adds(&s.pool, list...)
}

// Remove 移除池中一个节点。
// @index 目标成员的位置下标
// @return 被移除的节点
func (s *Shortlist) Remove(index int) *Node {
	return pool.Remove(&s.pool, index)
}

// Removes 移除池中多个节点。
// @indexes 位置下标序列
// @return 被移除的节点清单
func (s *Shortlist) Removes(i, size int) []*Node {
	return pool.Removes(&s.pool, i, size)
}

// Take 提取一个随机成员。
func (s *Shortlist) Take() *Node {
	return pool.Take(&s.pool)
}

// Takes 提取一些随机成员。
func (s *Shortlist) Takes(count int) []*Node {
	return pool.Takes(&s.pool, count)
}

// List 获取一个随机节点集。
// @count 最大数量
// @return 一个随机节点序列
func (s *Shortlist) List(count int) []*Node {
	return pool.List(&s.pool, count)
}

// Drop 提取全部成员。
// 原池会被清空，但其它设置被保留。
func (s *Shortlist) Drop() []*Node {
	return pool.Drop(&s.pool)
}

// Clean 清理无效连接（对端下线）
// 直接完成Finder的清理逻辑。
// 用户通常运行一个服务，定时调用该方法。
func (s *Shortlist) Clean(ctx context.Context) {
	start := time.Now()
	out := pool.Clean(ctx, &s.pool, offline)

	for its := range out {
		log.Printf("[%s] was cleaned from Shortlist\n", its)
	}
	log.Printf("Cleaning the shortlist took %s\n", time.Since(start))
}

// IsFulled 池是否已满员。
func (s *Shortlist) IsFulled() bool {
	return pool.IsFulled(&s.pool)
}

// Size 获取池当前大小。
func (s *Shortlist) Size() int {
	return pool.Size(&s.pool)
}

//
// 组网池
//////////////////////////////////////////////////////////////////////////////

// Finder Findings组网节点
type Finder struct {
	*Node                 // 对端节点
	Conn  *websocket.Conn // 当前 Websocket 连接
}

// NewFinder 新建一个Finder
func NewFinder(node *Node, conn *websocket.Conn) *Finder {
	return &Finder{
		Node: node,
		Conn: conn,
	}
}

// NewHost 请求对端发送一个UDP探测包。
// - 提供目标UDP地址和端口作为对端的发送目标。
// - 提供一个序列号标识，作为对端发送的内容。
// 注记：
// 服务器在接收到客户端的NAT探测请求后，需要随机选取一个Finder，
// 请求其连接的对端发送NewHost请求。
// @raddr 远端UDP地址
// @sn 标识序列号
// @return 通知是否成功发送的通道。
func (f *Finder) NewHost(raddr *net.UDPAddr, sn ClientSN) <-chan error {
	var err error
	var data []byte
	ch := make(chan error, 1)

	go func() {
		defer close(ch)
		defer func() { ch <- err }()

		// 消息编码
		data, err = stun.EncodeHosto(raddr, sn)
		if err != nil {
			return
		}
		// 按类型发送
		data, err = base.EncodeProto(base.COMMAND_STUN_HOST, data)
		if err != nil {
			return
		}
		// 网络请求
		err = f.Conn.WriteMessage(websocket.BinaryMessage, data)
		if err != nil {
			return
		}
		_, data, err = f.Conn.ReadMessage()
		if err != nil {
			return
		}
		// 对端需正确回应！
		if string(data) != base.CmdStunHostOK {
			err = ErrNewHost
		}
	}()
	return ch
}

// Quit 节点退出。
func (f *Finder) Quit() {
	f.Conn.Close()
}

// Finders 组网池。
// 结构和 Shortlist 相同，但方法集稍有差别。
type Finders struct {
	pool pool.Pool[Finder]
}

// NewFinders 创建一个连接池
func NewFinders(size int) *Finders {
	if size <= 0 {
		return nil
	}
	return &Finders{
		pool: *pool.NewPool[Finder](size),
	}
}

// Add 添加一个节点。
func (f *Finders) Add(node *Finder) error {
	return pool.Add(&f.pool, node)
}

// Remove 移除一个成员。
func (f *Finders) Remove(index int) *Finder {
	return pool.Remove(&f.pool, index)
}

// Dispose 清除目标连接节点。
// @conn 目标连接
// @return 被移除的目标节点
func (f *Finders) Dispose(conn *websocket.Conn) *Finder {
	test := func(node *Finder) bool {
		return conn == node.Conn
	}
	return pool.Dispose(&f.pool, test)
}

// Removes 移除多个成员。
func (f *Finders) Removes(i, size int) []*Finder {
	return pool.Removes(&f.pool, i, size)
}

// Get 引用一个随机成员。
func (f *Finders) Get() *Finder {
	// 无删除需求，忽略下标
	_, its := pool.Get(&f.pool)
	return its
}

// Take 提取一个随机成员。
func (f *Finders) Take() *Finder {
	return pool.Take(&f.pool)
}

// Size 返回节点池大小。
func (f *Finders) Size() int {
	return pool.Size(&f.pool)
}

// IsFulled 节点池是否满员。
func (f *Finders) IsFulled() bool {
	return pool.IsFulled(&f.pool)
}

//
// 应用支持
//////////////////////////////////////////////////////////////////////////////

// ErrApplNoTCP 应用节点不支持TCP。
var ErrApplNoTCP = errors.New("node is not support TCP")

// ErrApplNotPub 应用节点不是可直连节点。
var ErrApplNotPub = errors.New("node NAT level not Pub/FullC")

// Applier 应用端服务员
// 与 Finder 字段完全相同，但两者所支持的方法集不同。
type Applier struct {
	*Node                     // 对端节点
	*LinkPeer                 // 打洞关联节点
	Conn      *websocket.Conn // 当前连接（TCP）
}

// NewApplier 创建一个应用端服务员
func NewApplier(node *Node, peer *LinkPeer, conn *websocket.Conn) *Applier {
	return &Applier{
		Node:     node,
		LinkPeer: peer,
		Conn:     conn,
	}
}

// String 服务员的字符串表示（对端信息）
// 格式：IP:Port(Level)
func (a *Applier) String() string {
	return fmt.Sprintf("%s(%d)", a.Node.String(), a.Level)
}

// Quit 节点退出。
func (a *Applier) Quit() {
	a.Conn.Close()
}

// Appliers 应用端服务员缓存池。
type Appliers struct {
	pool pool.Pool[Applier]
}

// Applier 到期测试
// 下线或者存活时间过期。下线测试可能会需要较长时间。
// @long 存活期时长
func expireApplier(a *Applier, long time.Duration) bool {
	return time.Now().Before(a.Start.Add(long)) || offline(a.Node)
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

// AddTCP 添加对端支持TCP的服务员。
// 与Add方法相同，但增加了必要的检查。是一个便捷方法。
// 使用：
// 在向仅包含TCP支持的节点的池中添加成员时使用本方法。
// 约束：
// 对端的NAT类型必须是 Pub/FullC，否则添加失败。
// @node 目标应用端
func (a *Appliers) AddTCP(node *Applier) error {
	if node.Network != "tcp" {
		return ErrApplNoTCP
	}
	if node.Level != NAT_LEVEL_NULL {
		return ErrApplNotPub
	}
	return pool.Add(&a.pool, node)
}

// Remove 移除目标成员
func (a *Appliers) Remove(index int) *Applier {
	return pool.Remove(&a.pool, index)
}

// Removes 移除多个成员。
func (a *Appliers) Removes(i, size int) []*Applier {
	return pool.Removes(&a.pool, i, size)
}

// Get 引用一个随机成员。
// @return1 目标成员的位置下标
// @return2 目标成员
func (a *Appliers) Get() (int, *Applier) {
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

	for list := range out {
		for _, its := range list {
			its.Quit()
		}
		cnt += len(list)
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

// 双协议池组
// 包含支持TCP和UDP两种链路的节点池汇总。
// 其中支持TCP的只收录可直连（Pub/FullC）的节点。
// PoolsUDP:
// - [0]: Pub/FullC
// - [1]: RC
// - [2]: P-RC
// - [3]: Sym
// 注记：
// 对于想提供TCP中转服务（TRUN）的节点，其自身可以作为一种应用来实现。
// 其它应用请求它们的信息、申请服务。。
type appliersTeam struct {
	PoolTCP  *Appliers // 支持TCP的节点池
	PoolsUDP appliers4 // 支持UDP的节点池，包含NAT全类型
}

// AppliersPool 应用服务员池组集
// 包含任意应用类型，每一个类型对应一个按NAT分类的双协议池组。
// key: 应用类型名（kind:name）
type AppliersPool map[string]appliersTeam

// NewClientsPool 创建一个应用服务员池组集
func NewAppliersPool() AppliersPool {
	return make(map[string]appliersTeam)
}

// Init 初始化应用池组。
// 每一种应用初始使用时都需要调用该初始化函数。
// 注意：
// 不支持并发安全，因此用户需要在程序最开始时初始化自己支持的所有应用。
// @kind 应用类型名（kind:name）
// @size 池大小限制
// @cleanlen 清理的片段长度
func (cp AppliersPool) Init(kind string, size int) {
	cp[kind] = appliersTeam{
		PoolsUDP: newAppliers4(size),
		PoolTCP:  NewAppliers(size),
	}
}

// Appliers 获取一个应用服务员集。
// level:
// - NAT_LEVEL_NULL
// - NAT_LEVEL_RC
// - NAT_LEVEL_PRC
// - NAT_LEVEL_SYM
// 如果网络是TCP，则level必须是 Pub/FullC 类型（0）。
//
// @kind 应用类型名
// @net 网络协议类型（tcp|udp）
// @level 目标NAT层级（0 ~ 3）
// @return 目标类型的节点池
func (cp AppliersPool) Appliers(kind string, net string, level NatLevel) (*Appliers, error) {
	cs2p, ok := cp[kind]
	if !ok {
		return nil, ErrAppKind
	}
	switch net {
	case "tcp":
		if level != NAT_LEVEL_NULL {
			return nil, ErrNatLevel
		}
		return cs2p.PoolTCP, nil
	case "udp":
		return cs2p.PoolsUDP[level], nil
	}
	return nil, ErrNetwork
}

// AppliersUDP 提取目标类型的UDP打洞信息组
// 如果不支持目标类型，返回nil。
// 注：
// Sym 在 Pub/FullC 主动请求时有用，但单向连接无需打洞。
func (cp AppliersPool) AppliersUDP(kind string) []*Appliers {
	cs2p, ok := cp[kind]
	if !ok {
		log.Printf("The kind of [%s] not supported.\n", kind)
		return nil
	}
	return cs2p.PoolsUDP[:]
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
		cs2p, ok := cp[kind]
		if !ok {
			continue
		}
		for _, cs := range cs2p.PoolsUDP {
			go cs.Clean(ctx, long)
		}
		go cs2p.PoolTCP.Clean(ctx, long)
	}
}

//
// 工具函数集
//////////////////////////////////////////////////////////////////////////////

// WebsocketDial 创建一个websocket拨号
// 如果传递超时时长long为0或负值，则采用默认的30秒钟。
func WebsocketDial(ip netip.Addr, port int, long time.Duration) (*websocket.Conn, error) {
	u := url.URL{
		Scheme: "wss",
		Path:   "/ws", // 兼容/上的监听
	}
	if ip.Is4() {
		u.Host = fmt.Sprintf("%s:%d", ip, port)
	} else {
		u.Host = fmt.Sprintf("[%s]:%d", ip, port)
	}
	if long <= 0 {
		long = defaultTimeout
	}
	// P2P 无需证书验证
	dialer := &websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: long,
	}
	// 没有 request Header 需求，
	// 因此忽略 http.Response 返回值
	conn, _, err := dialer.Dial(u.String(), nil)

	return conn, err
}

// 节点集转换
// 主要用于 protobuf 序列化传输。
func toPeers(nodes []*Node) []*Peer {
	buf := make([]*Peer, 0, len(nodes))

	for _, nd := range nodes {
		buf = append(buf, &Peer{Ip: nd.IP.AsSlice(), Port: int32(nd.Port)})
	}
	return buf
}

// 节点集转换
// 用于从 protobuf 传输的数据中解码提取。
func toNodes(peers []*Peer) []*Node {
	buf := make([]*Node, 0, len(peers))

	for _, p := range peers {
		buf = append(buf, NewFromPeer(p))
	}
	return buf
}

// 下线判断。
// 主要用于节点连接测试&清理操作，采用默认超时。
// 注意：会记录节点的Ping值，-1表示不可达。
// @node 目标节点
// @return 下线返回true，反之为false
func offline(node *Node) bool {
	start := time.Now()

	if err := Online(node.IP, node.Port, -1); err != nil {
		node.Ping = -1
		log.Printf("[%s] is unreachable because %s\n", node, err)
		return true
	}
	node.Ping = time.Since(start)

	return false
}

// Onlines 节点集在线测试
// 检查目标节点集内的节点是否在线。
// 测试过程会阻塞进程，达到超时时间后会返回已成功的集合。
// 如果所有节点都在线，则可能提前返回。
// 注意：
// 会记录节点的ping时间，-1值表示不可达。
// @nodes 目标节点集
// @long 测试超时时间限定，零值表示采用系统默认值
// @return 在线的节点集成员
func Onlines(nodes []*Node, long time.Duration) []*Node {
	var wg sync.WaitGroup
	buf := make([]*Node, 0, len(nodes))

	// 带适量缓存，
	// 充分利用节点的反应速度（快者在前）
	out := make(chan *Node, 3)

	for _, node := range nodes {
		wg.Add(1)

		// 并行测试
		go func(node *Node) {
			defer wg.Done()
			start := time.Now()

			if err := Online(node.IP, node.Port, long); err != nil {
				node.Ping = -1
				log.Printf("[%s] is unreachable because %s\n", node, err)
				return
			}
			node.Ping = time.Since(start)

			out <- node
		}(node)
	}
	go func() {
		wg.Wait()
		close(out)
	}()

	// 阻塞式提取
	for node := range out {
		buf = append(buf, node)
	}
	return buf
}

// Online 测试节点是否在线
// 返回nil表示正常，返回任何其它错误表示不在线。
// 测试采用临时连接，结束即关闭。
// @ip 目标地址
// @port 目标端口
// @long 拨号等待超时时间，0值采用系统默认值
func Online(ip netip.Addr, port int, long time.Duration) error {
	conn, err := WebsocketDial(ip, port, long)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 发送同类问候
	// 需对方回应正确的消息以判断是否同为Findings节点。
	// 因此不是 websocket.PingMessage
	err = conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindPing))
	if err != nil {
		return err
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if string(msg) != base.CmdFindOK {
		return ErrOnline
	}
	return nil
}

// TCPPeer 提取支持TCP的关联节点。
// 传递direct为true表示仅限于可直连的Pub/FullC节点。
// 如果不满足条件，返回nil。
func TCPPeer(lp *LinkPeer, direct bool) *Node {
	if lp.Network != "tcp" {
		return nil
	}
	if direct && lp.Level != NAT_LEVEL_NULL {
		return nil
	}
	return New(lp.IP, lp.Port)
}
