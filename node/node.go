// 节点模块
// 包含Findings候选池、连接池以及应用节点池的支持。
package node

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand"
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

// 默认超时时间
const defaultTimeout = time.Second * 30

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
	// 候选池无清理行为，因此清理函数为nil。
	return &Shortlist{
		pool: *pool.NewPool[Node](size, nil),
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
func (s *Shortlist) Removes(indexes ...int) []*Node {
	return pool.Removes(&s.pool, indexes...)
}

// Take 提取一个随机成员。
func (s *Shortlist) Take() *Node {
	return pool.Take(&s.pool)
}

// Takes 提取一些随机成员。
func (s *Shortlist) Takes(count int) []*Node {
	return pool.Takes(&s.pool, count)
}

// Drop 提取全部成员。
// 原池会被清空，但其它设置被保留。
func (s *Shortlist) Drop() []*Node {
	return pool.Drop(&s.pool)
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
	*Node                     // 对端节点
	*LinkPeer                 // 打洞关联节点
	Conn      *websocket.Conn // 当前 Websocket 连接
}

// NewFinder 新建一个Finder
func NewFinder(node *Node, peer *LinkPeer, conn *websocket.Conn) *Finder {
	return &Finder{
		Node:     node,
		LinkPeer: peer,
		Conn:     conn,
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

// Exit 节点退出。
func (f *Finder) Exit() {
	f.Conn.Close()
}

// String 节点的字符串表示。
// 显示为节点当前TCP连接的相关信息。
// 格式：IP:Port(Level)
func (f *Finder) String() string {
	return fmt.Sprintf("%s(%d)", f.Node.String(), f.Level)
}

// Finders 组网池。
// 结构和 Shortlist 相同，但方法集稍有差别。
type Finders struct {
	pool pool.Pool[Finder]
}

// NewFinders 创建一个连接池
func NewFinders(size int) *Finders {
	return &Finders{
		pool: *pool.NewPool(size, func(f *Finder) bool {
			return offline(f.Node)
		}),
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

// Removes 移除多个成员。
func (f *Finders) Removes(indexes ...int) []*Finder {
	return pool.Removes(&f.pool, indexes...)
}

// Get 引用一个随机成员。
// 主要用于 NewHost 操作的目标获取。
// 可以比较 Finder.Conn 值来判断是否为自身。
func (f *Finders) Get() *Finder {
	// 无删除需求，忽略下标
	_, its := pool.Get(&f.pool)
	return its
}

// Take 提取一个随机成员。
func (f *Finders) Take() *Finder {
	return pool.Take(&f.pool)
}

// Clean 清理无效连接（对端下线）
// 直接完成Finder的清理逻辑。
// 用户通常运行一个服务，定时调用该方法。
func (f *Finders) Clean() {
	out := pool.Clean(&f.pool, -1)
	start := time.Now()

	for its := range out {
		log.Printf("[%s] was cleaned from Finders\n", its)
		its.Exit()
	}
	log.Printf("Cleaning the finders took %s\n", time.Since(start))
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

// Appliers 应用端服务员集（缓存池）。
// 内部存储区是一个预申请的切片空间，向尾部添加新成员。
// 当池满时，添加新成员会触发清理操作。
// 清理操作只是把尾部的一段新成员移动到头部，同时记忆位置游标（清理起点）。
// 清理效果：
// 维持池的大小符合要求，旧成员的过期时间是相对的，取决于新加入成员的速度。
// 注意：
// 这是一种概略算法，对端中断连接后的快速移除会破坏成员的时序性。
//
// ！这不是一个好的策略
// 会导致不活跃的池，其节点的有效性下降：不活跃，服务质量就差，就更不活跃……
type Appliers struct {
	queue    []*Applier // 存储区
	maxSize  int        // 池大小限制
	cleanLen int        // 清理长度
	cursor   int        // 清理点位置游标
	mu       sync.Mutex
}

// NewAppliers 创建集合（缓存池）。
// 池大小size需为一个大于零的数，且不能小于清理长度cleanlen
// 通常，size 为 cleanlen 的整数倍且2倍以上。
// 清理长度cleanlen不可为零。
// @size 池大小限制
// @cleanlen 清理的片段长度。
// @net 支持的网络类型（tcp|udp）
func NewAppliers(size, cleanlen int) *Appliers {
	if size < 1 {
		log.Fatalln("[Fatal] client pool size is too small.")
	}
	if cleanlen <= 0 {
		log.Fatalln("[Fatal] clean length is invalid.")
	}
	return &Appliers{
		queue:    make([]*Applier, 0, size),
		maxSize:  size,
		cleanLen: cleanlen,
	}
}

// Add 添加成员到缓存池。
// 如果池已满会自动触发强制清理操作，因此总会添加成功。
// @node 目标应用端
func (a *Appliers) Add(node *Applier) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.queue) >= a.maxSize {
		a.cursor = a.forceClean(a.cursor, a.cleanLen)
	}
	log.Printf("Add {%s} to the applier pool.\n", node.String())

	a.queue = append(a.queue, node)
}

// AddTCP 添加对端支持TCP的服务员。
// 与Add方法相同，但增加了对所支持协议的检查。
// 当在向仅包含TCP支持的节点的池中添加成员时使用该方法。
// 约束：
// 对端的NAT类型必须是 Pub/FullC，否则添加失败。
// @node 目标应用端
func (a *Appliers) AddTCP(node *Applier) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if node.Network != "tcp" {
		return ErrApplNoTCP
	}
	if node.Level != NAT_LEVEL_NULL {
		return ErrApplNotPub
	}
	if len(a.queue) >= a.maxSize {
		a.cursor = a.forceClean(a.cursor, a.cleanLen)
	}
	log.Printf("Add {%s} to the applier pool.\n", node.String())

	a.queue = append(a.queue, node)
	return nil
}

// Remove 移除目标成员
func (c *Appliers) Remove(node *Applier) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.queue = c.deleteOne(node)
}

// List 获取一个成员清单
// 如果指定的长度为零或负值或超过了池内节点数，返回全部节点。
// 返回的集合成员为随机抽取，如果返回全集，则已随机化排列。
// @size 获取的清单长度。
// @return 一个随机提取的成员表。
func (c *Appliers) List(size int) []*Applier {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.queue) == 0 {
		return []*Applier{}
	}
	if size > len(c.queue) || size <= 0 {
		size = len(c.queue)
	}
	list := make([]*Applier, 0, size)

	for _, ix := range randomIndexs(size, len(c.queue)) {
		list = append(list, c.queue[ix])
	}
	return list
}

// Get 获取一个成员引用（随机）
func (c *Appliers) Get() *Applier {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.queue) == 0 {
		return nil
	}
	return c.queue[rand.Intn(len(c.queue))]
}

// Clean 清理缓存池
// 移除入池时间太久的成员。
// 从游标位置开始检查，记录连续的片段并移除。
// 注意：
// 如果对端断开连接，外部可能将之从池中移除。因此会打断节点排列的时序性。
// 所以这只是一种概略话的清理。
// @long 指定过期时间长度
func (c *Appliers) Clean(long time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.queue) == 0 {
		return
	}
	cnt := 0
	for i := c.cursor; i < len(c.queue); i++ {
		node := c.queue[i]
		// 连续段检查
		// 只要碰到较新的加入时间即终止。
		if time.Now().Before(node.Start.Add(long)) {
			break
		}
		cnt++
	}
	if cnt == 0 {
		return
	}
	c.cursor = c.liveClean(c.cursor, cnt)
}

// Size 返回缓存池大小
func (c *Appliers) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.queue)
}

// IsFulled 缓存池是否满员
func (c *Appliers) IsFulled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.queue) >= c.maxSize
}

// Reset 重置缓存池
// 保持原始存储区，不申请新的内存空间。
func (c *Appliers) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.queue = c.queue[:0]
	c.cursor = 0
}

// 强制清理缓存池。
// 取末尾的新成员移到前段覆盖旧成员，收缩切片腾出空间备用。
// 应当在池满时才调用。
// 注意：
// 这里没有绝对的过期时间，只是移除相对较旧的成员。
// @i 清理的起始下标位置
// @clen 待清理的片区长度
// @return 新的下标位置
func (c *Appliers) forceClean(i, clen int) int {
	end := i + clen
	z := len(c.queue) - clen

	// 池大小已小于清理长度
	if z <= 0 {
		return i
	}
	// 已超出尾部，末尾新鲜节点移到头部。
	if end > len(c.queue) {
		z = i
		end = len(c.queue) - i
		i = 0
	}
	// 末尾新值前移，后段可能有交叠覆盖
	copy(c.queue[i:end], c.queue[z:])

	// 如果末尾交叠
	// 覆盖交叠的应为更新鲜的节点，保留。
	if end > z {
		z = end
	}
	c.queue = c.queue[:z]

	return end % len(c.queue)
}

// 活跃性清理。
// 行为类似forceClean，但优先考虑清理段移除（末尾交叠区处理）。
// 清理段长度由时间检查而来，故必然在池内。
// @i 清理的起始下标
// @clen 待清理的片区长度
func (c *Appliers) liveClean(i, clen int) int {
	end := i + clen
	z := len(c.queue) - clen
	lap := 0

	// 如果末尾交叠
	if end > z {
		lap = end - z
		z, end = end, z // 交叠区等待移除，暂不管
	}
	// 末尾新值前移
	copy(c.queue[i:end], c.queue[z:])

	// 保证交叠部分移除
	c.queue = c.queue[:z-lap]

	return end % len(c.queue)
}

// 移除一个成员。
// 采用快速移除法：将末尾的新成员移动到被删除成员的位置。
// 有一个优化处理以避免末尾新成员移动到最前段，从而被很快清理掉（forceClean）。
// 实现：
// 如果目标所在位置太靠前（1/3），会先在中段随机选取一个成员作为中间换位。
// 即取随机位置的成员前移覆盖，然后末尾新节点移动到原随机位置。
// 返回：移除成员后的总成员集
func (c *Appliers) deleteOne(node *Applier) []*Applier {
	i := 0
	var tmp *Applier
	list := c.queue

	for i, tmp = range list {
		if tmp == node {
			break
		}
	}
	if tmp == nil {
		return list
	}
	z := len(list) - 1

	// 太靠前
	if i < z/3 {
		// 增加中间换手，随机位
		n := rand.Intn(z/3) + z/3

		list[i] = list[n]
		i = n
	}
	list[i] = list[z]

	return list[:z]
}

// 按NAT分类的应用服务员池组
// [0] - Pub&FullC
// [1] - RC
// [2] - P-RC
// [3] - Sym
type appliers4 [4]*Appliers

func newAppliers4(size, cleanlen int) appliers4 {
	var app4 [4]*Appliers

	for i := 0; i < 4; i++ {
		app4[i] = NewAppliers(size, cleanlen)
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
// @kind 应用类型名
// @size 池大小限制
// @cleanlen 清理的片段长度
func (cp AppliersPool) Init(kind string, size, cleanlen int) {
	cp[kind] = appliersTeam{
		PoolsUDP: newAppliers4(size, cleanlen),
		PoolTCP:  NewAppliers(size, cleanlen),
	}
}

// Appliers 获取一个应用服务员集。
// level:
// - NAT_LEVEL_NULL
// - NAT_LEVEL_RC
// - NAT_LEVEL_PRC
// - NAT_LEVEL_SYM
// 如果网络是TCP，则level仅支持 Pub/FullC 类型值（0）。
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
// @kinds 目标应用名称集
// @long 有效期时长
func (cp AppliersPool) Clean(kinds []string, long time.Duration) {
	for _, kind := range kinds {
		cs2p, ok := cp[kind]
		if !ok {
			continue
		}
		for _, cs := range cs2p.PoolsUDP {
			go cs.Clean(long)
		}
		go cs2p.PoolTCP.Clean(long)
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
// 因此错误记入日志。
// @node 目标节点
// @return 下线返回true，反之为false
func offline(node *Node) bool {
	if err := Online(node.IP, node.Port, -1); err != nil {
		log.Printf("[%s] is unreachable because %s\n", node, err)
		return true
	}
	return false
}

// 生成不重复随机值序列。
// 用于随机索引值生成，在一个大的切片中随机提取成员。
// @n 生成的数量（序列长度）
// @max 最大整数值的上边界（不含）
func randomIndexs(n, max int) []int {
	nums := make(map[int]bool)
	list := make([]int, n)

	if n > max {
		log.Fatalln("[Fatal] random amount large than max.")
	}
	for i := 0; i < n; {
		num := rand.Intn(max)
		if !nums[num] {
			nums[num] = true
			list[i] = num
			i++
		}
	}
	return list
}

// Onlines 节点集在线测试
// 检查目标节点集内的节点是否在线。
// 测试过程会阻塞进程，达到超时时间后会返回已成功的集合。
// 如果所有节点都在线，则可能提前返回。
// @nodes 目标节点集
// @long 测试超时时间限定，零值表示采用系统默认值
// @return 在线的节点集成员
func Onlines(nodes []*Node, long time.Duration) []*Node {
	var wg sync.WaitGroup
	buf := make([]*Node, 0, len(nodes))
	out := make(chan *Node)

	for _, node := range nodes {
		wg.Add(1)

		// 并行测试
		go func(node *Node) {
			defer wg.Done()
			start := time.Now()

			if err := Online(node.IP, node.Port, long); err != nil {
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
