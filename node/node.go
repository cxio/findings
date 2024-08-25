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

	"github.com/cxio/findings/config"
	"github.com/cxio/findings/stun"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"
)

// NAT 层级
type NatLevel = stun.NatLevel

// UDP打洞包
type Puncher = stun.Puncher

// 序列号引用
type ClientSN = stun.ClientSN

// 在线测试错误
var errOnline = errors.New("the target node is offline")

// 局部需用常量引用。
// 注：主要用于 Clients4 类型取成员值。
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
// 节点通用
//////////////////////////////////////////////////////////////////////////////

// Node 节点结构（TCP）
// 运行时的节点信息，用于实时连接的缓存。
type Node struct {
	IP     netip.Addr    // IP
	Port   uint16        // 端口
	Joined time.Time     // 连接加入时间
	Ping   time.Duration // 节点距离
}

// New 创建节点
// @addr 节点网络地址（IP:Port），注意格式合法。
func New(addr string) *Node {
	ipp, err := netip.ParseAddrPort(addr)

	if err != nil {
		log.Println("Error network address", addr)
		return nil
	}
	return &Node{
		IP:     ipp.Addr(),
		Port:   ipp.Port(),
		Joined: time.Now(),
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
	return &Node{
		IP:     ap.Addr(),
		Port:   ap.Port(),
		Joined: time.Now(),
	}
}

// NewFromPeer 从传输数据Peer构造。
// 解析错误返回nil（忽略、容错），避免恶意破坏。
func NewFromPeer(p *Peer) *Node {
	ip, ok := netip.AddrFromSlice(p.Ip)
	if !ok {
		log.Println("Error from parse Peer's ip:", p)
		return nil
	}
	return &Node{IP: ip, Port: uint16(p.Port), Joined: time.Now()}
}

// String 字符串表示
// 格式：IP:Port
// 安全：不提供时间状态，隐私安全考虑。
func (nd *Node) String() string {
	return netip.AddrPortFrom(nd.IP, nd.Port).String()
}

// Pool 通用节点池。
// 主要用于Findings的候选节点区。
type Pool struct {
	nodes   []*Node
	maxSize int
	mu      sync.Mutex
}

// NewPool 新建一个节点池
func NewPool(size int) *Pool {
	return &Pool{
		nodes:   make([]*Node, 0, size),
		maxSize: size,
	}
}

// Add 添加一个新节点。
// 返回值：
// - false 表示池已满不能再添加新成员。
// - true 表示添加成功。
func (p *Pool) Add(node *Node) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.nodes) >= p.maxSize {
		log.Println("The node pool is fulled.")
		return false
	}
	p.nodes = append(p.nodes, node)
	return true
}

// AddNodes 添加节点集
// 如果不是强制添加，当池满的时候即停止。
// 如果添加的集合超过池余量，则取前段成员添加。
// @nodes 待添加的节点集
// @force 是否强制添加（可超出池大小额度）
func (p *Pool) AddNodes(nodes []*Node, force bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	n := p.maxSize - len(p.nodes)
	if n <= 0 && !force {
		return
	}
	if n < len(nodes) && !force {
		nodes = nodes[:n]
	}
	p.nodes = append(p.nodes, nodes...)
}

// Remove 移除一个节点。
// 注：无需保持池中成员的顺序。
func (p *Pool) Remove(node *Node) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nodes = p.removeNode(node, p.nodes)
}

// RemoveList 移除多个成员
func (p *Pool) RemoveList(list []*Node) {
	p.mu.Lock()
	defer p.mu.Unlock()

	nodes := p.nodes

	for _, node := range list {
		nodes = p.removeNode(node, nodes)
	}
	p.nodes = nodes
}

// Trim 清理多出的成员。
// 简单截断末尾部分即可，无顺序要求。
// @return 被清理的成员
func (p *Pool) Trim() []*Node {
	p.mu.Lock()
	defer p.mu.Unlock()

	size := len(p.nodes) - p.maxSize
	if size <= 0 {
		return nil
	}
	buf := make([]*Node, size)

	copy(buf, p.nodes[size:])
	p.nodes = p.nodes[:size]

	return buf
}

// List 返回一个成员清单
// 如果池中的成员数不足，会返回仅有的成员集。
// 返回集成员是随机排列的。
// 如果传递size为0或负值，会返回全部成员的一个随机排列清单。
// @size 返回集大小上限
func (p *Pool) List(size int) []*Node {
	p.mu.Lock()
	defer p.mu.Unlock()

	if size > len(p.nodes) || size <= 0 {
		size = len(p.nodes)
	}
	list := make([]*Node, 0, size)

	for _, ix := range randomIndexs(size, len(p.nodes)) {
		list = append(list, p.nodes[ix])
	}
	return list
}

// Pick 抽取一个成员（随机）
func (p *Pool) Pick() *Node {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.nodes) == 0 {
		return nil
	}
	i := rand.Intn(len(p.nodes))

	node := p.nodes[i]
	p.nodes = p.removeIndex(i, p.nodes)

	return node
}

// Size 返回节点池大小
func (p *Pool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.nodes)
}

// IsFulled 节点池是否满员
func (p *Pool) IsFulled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.nodes) >= p.maxSize
}

// MaxSize 返回节点池大小限制
func (p *Pool) MaxSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.maxSize
}

// Nodes 返回池节点的原始集。
// 如果对返回集进行修改，会影响池内部。
func (p *Pool) Nodes() []*Node {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.nodes
}

// 移除列表中一个成员
// 快速移除：用末尾成员替换，不维持原列表成员顺序。
// 返回被移除成员后的列表
// @node 目标成员
// @list 目标列表
// @return 移除成员后的列表
func (p *Pool) removeNode(node *Node, list []*Node) []*Node {
	for i, nd := range list {
		if nd == node {
			return p.removeIndex(i, list)
		}
	}
	return list
}

// 移除目标位置的成员
// 快速移除方式：用末尾的成员填充即可。
// @i 目标位置
// @return 移除目标后的集合
func (p *Pool) removeIndex(i int, list []*Node) []*Node {
	n := len(list)
	list[i] = list[n-1]
	return list[:n-1]
}

//
// Findings
//////////////////////////////////////////////////////////////////////////////

// Finder Findings在线节点
type Finder struct {
	*Node
	Conn *websocket.Conn
}

// NewFinder 新建一个Finder
func NewFinder(node *Node, conn *websocket.Conn) *Finder {
	return &Finder{Node: node, Conn: conn}
}

// NewHost 请求对端向目标发送一个UDP探测包。
// @raddr 远端UDP地址
// @sn 标识序列号
// @return 返回的通道用于通知是否成功发送。
func (f *Finder) NewHost(raddr *net.UDPAddr, sn ClientSN) <-chan bool {
	ch := make(chan bool, 1)
	go func() {
		defer close(ch)

		// 指出服务类型
		err := f.Conn.WriteMessage(websocket.TextMessage, []byte(config.CmdStunHost))
		if err != nil {
			ch <- false
			log.Println(err)
			return
		}
		// 实际发送数据
		data, err := EncodeClientUDP(raddr, sn)
		if err != nil {
			ch <- false
			log.Println(err)
			return
		}
		err = f.Conn.WriteMessage(websocket.BinaryMessage, data)
		if err != nil {
			ch <- false
			log.Println(err)
			return
		}
		_, reply, err := f.Conn.ReadMessage()
		if err != nil {
			ch <- false
			log.Println(err)
			return
		}
		// 注意：对端需正确回应！
		ch <- string(reply) == config.CmdStunHosted
	}()
	return ch
}

// Finders 本网节点连接池。
// 每次清理时会遍历全池查找时间最老节点，适用于小规模缓存。
type Finders struct {
	nodes   map[*websocket.Conn]*Finder
	maxSize int
	mu      sync.Mutex
}

// NewFinders 创建一个连接池
func NewFinders(size int) *Finders {
	return &Finders{
		nodes:   make(map[*websocket.Conn]*Finder, size),
		maxSize: size,
	}
}

// Add 添加一个节点
// 外部调用时，通常会先移除一个成员后再添加。
// 返回值错误表示添加失败，否则添加成功。
func (f *Finders) Add(node *Finder) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.nodes) >= f.maxSize {
		return errors.New("the finder pool is fulled")
	}
	f.nodes[node.Conn] = node
	log.Printf("Add {%s} to the finder pool.", node.String())

	return nil
}

// Remove 移除一个成员
// 没有错误返回表示移除成功（存在该目标）
func (f *Finders) Remove(conn *websocket.Conn) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.nodes[conn]; ok {
		delete(f.nodes, conn)
		return nil
	}
	return errors.New("the finder pool is emptyed")
}

// RemoveList 移除多个成员
func (f *Finders) RemoveList(list []*Finder) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, node := range list {
		delete(f.nodes, node.Conn)
	}
}

// Trim 清理多出的成员。
// 仅简单移除头部成员即可，无顺序要求。
// @return 被清理的成员
func (f *Finders) Trim() []*Finder {
	f.mu.Lock()
	defer f.mu.Unlock()

	size := len(f.nodes) - f.maxSize
	if size <= 0 {
		return nil
	}
	buf := make([]*Finder, 0, size)

	for conn := range f.nodes {
		if size <= 0 {
			break
		}
		buf = append(buf, f.nodes[conn])
		size--
		delete(f.nodes, conn)
	}
	return buf
}

// Pick 提取一个成员（随机）
// 取出的成员会从池中移除，行为类似Remove但无需指定目标。
func (f *Finders) Pick() *Finder {
	f.mu.Lock()
	defer f.mu.Unlock()

	var node *Finder

	if node = f.random(); node != nil {
		delete(f.nodes, node.Conn)
	}
	return node
}

// Random 引用一个随机成员
func (f *Finders) Random() *Finder {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.random()
}

// List 返回池中成员清单
func (f *Finders) List() []*Finder {
	f.mu.Lock()
	defer f.mu.Unlock()

	list := make([]*Finder, 0, len(f.nodes))
	for _, node := range f.nodes {
		list = append(list, node)
	}
	return list
}

// Finder 返回目标连接的属主节点。
// 如果池中没有成员或目标不存在，返回nil。
func (f *Finders) Get(conn *websocket.Conn) *Finder {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.nodes) == 0 {
		return nil
	}
	return f.nodes[conn]
}

// Clean 清理无效连接（已被对端关闭）
func (f *Finders) Clean() {
	dels := make([]*websocket.Conn, 0)
	list := f.List()

	// 阻塞获取
	for conn := range f.clean(list) {
		dels = append(dels, conn)
	}
	if len(dels) == 0 {
		return
	}
	// 锁定批量移除
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, conn := range dels {
		delete(f.nodes, conn)
	}
}

// Size 返回节点池大小
func (f *Finders) Size() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.nodes)
}

// IsFulled 节点池是否满员
func (f *Finders) IsFulled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.nodes) >= f.maxSize
}

// 引用一个随机成员
func (f *Finders) random() *Finder {
	if len(f.nodes) == 0 {
		return nil
	}
	var node *Finder
	cnt := rand.Intn(len(f.nodes))

	for _, node = range f.nodes {
		if cnt == 0 {
			break
		}
		cnt--
	}
	return node
}

// 清理已经关闭的连接。
// 并发检查传入的节点清单，测试是否已经被对端关闭。
// 已经关闭的连接从out发送出去。
// 如果已经遍历检查完毕，则关闭发送通道（通知外部结束）。
func (f *Finders) clean(nodes []*Finder) chan *websocket.Conn {
	var wg sync.WaitGroup
	out := make(chan *websocket.Conn)

	for _, node := range nodes {
		wg.Add(1)

		go func(conn *websocket.Conn) {
			defer wg.Done()

			err := conn.WriteMessage(websocket.PingMessage, []byte("ping"))
			if err == nil {
				return // 正常，conn维持开启
			}
			// 这边也关闭
			conn.Close()
			log.Println("Finder lost because:", err)

			out <- conn
		}(node.Conn)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

//
// 应用支持
//////////////////////////////////////////////////////////////////////////////

// Client 应用端节点
type Client struct {
	*Node
	*Puncher

	// 当前连接（TCP）
	Conn *websocket.Conn
}

// NewClient 创建一个应用端节点
func NewClient(node *Node, conn *websocket.Conn) *Client {
	return &Client{Node: node, Conn: conn}
}

// SetPunch 设置打洞信息
// 注：需要后期读取连接才能获取，因此为单独的方法。
func (c *Client) SetPunch(p *Puncher) {
	c.Puncher = p
}

// String 应用端节点的字符串表示
// 格式：IP:Port(Level)
func (c *Client) String() string {
	return fmt.Sprintf("%s(%s)", c.Node.String(), NatNames[c.Level])
}

// Clients 应用端节点池。
// 内部存储区是一个预申请的切片空间，向尾部添加新节点。
// 当池满时，添加新节点会触发清理操作。
// 清理操作只是把尾部的一段新节点移动到头部，同时记忆位置游标（清理起点）。
// 清理效果：
// 维持池的大小符合要求，旧节点的过期时间是动态的，取决于新加入节点的速度。
// 注意：
// 这是一种概略算法，节点中断连接后的快速移除会破坏成员的时序性。
type Clients struct {
	nodes    []*Client // 全集区
	maxSize  int       // 池大小限制
	cleanLen int       // 清理长度
	cursor   int       // 清理点位置游标
	mu       sync.Mutex
}

// NewClients 创建节点池
// 池大小size需为一个大于零的数，且不能小于清理长度cleanlen
// 通常，size 为 cleanlen 的整数倍且2倍以上。
// 清理长度cleanlen不可为零。
// @size 池大小限制
// @cleanlen 清理的片段长度。
func NewClients(size, cleanlen int) *Clients {
	if size < 1 {
		log.Fatal("The pool size is too small.")
	}
	if cleanlen <= 0 {
		log.Fatal("The cleaning length is invalid.")
	}
	return &Clients{
		nodes:    make([]*Client, 0, size),
		maxSize:  size,
		cleanLen: cleanlen,
	}
}

// Add 添加节点到节点池
// 总是会添加成功。如果池已满会自动触发强制清理操作。
func (c *Clients) Add(node *Client) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.nodes) >= c.maxSize {
		c.cursor = c.forceClean(c.cursor, c.cleanLen)
	}
	c.nodes = append(c.nodes, node)
	log.Printf("Add {%s} to the client pool.", node.String())
}

// Remove 移除目标成员
// 采用快速移除算法：将末尾的新成员移动到被删除成员的位置。
// 可能增加一个中间换手环节，避免最新成员被移动到太前端而被很快清理掉。
func (c *Clients) Remove(node *Client) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nodes = c.deleteOne(node)
}

// List 获取一个节点清单
// 如果指定的长度为零或负值或超过了池内节点数，返回全部节点。
// 返回的集合成员为随机抽取，如果返回全集，则已随机化排列。
// @size 获取的清单长度。
// @return 一个随机提取的节点集。
func (c *Clients) List(size int) []*Client {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.nodes) == 0 {
		return []*Client{}
	}
	if size > len(c.nodes) || size <= 0 {
		size = len(c.nodes)
	}
	list := make([]*Client, 0, size)

	for _, ix := range randomIndexs(size, len(c.nodes)) {
		list = append(list, c.nodes[ix])
	}
	return list
}

// Clean 清理节点池
// 移除入池时间太久的节点。
// 从游标位置开始检查，记录连续的片段并移除。
// 注意：
// 如果节点断开连接，外部可能将之从池中移除。因此会打断节点排列的时序性。
// 所以这只是一种概略话的清理。
// @long 指定过期时间长度
func (c *Clients) Clean(long time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.nodes) == 0 {
		return
	}
	cnt := 0
	for i := c.cursor; i < len(c.nodes); i++ {
		node := c.nodes[i]
		// 连续段检查
		// 只要碰到较新的加入时间即终止。
		if time.Now().Before(node.Joined.Add(long)) {
			break
		}
		cnt++
	}
	if cnt == 0 {
		return
	}
	c.cursor = c.liveClean(c.cursor, cnt)
}

// Size 返回节点池大小
func (c *Clients) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.nodes)
}

// IsFulled 节点池是否满员
func (c *Clients) IsFulled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.nodes) >= c.maxSize
}

// Reset 重置节点池
// 保持原始存储区，不申请新的内存空间。
func (c *Clients) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nodes = c.nodes[:0]
	c.cursor = 0
}

// 强制清理节点池。
// 取末尾的新节点移到前段覆盖旧节点，收缩切片腾出空间备用。
// 应当在池满时才调用。
// 注意：
// 这里没有绝对的过期时间，只是移除相对较旧的成员。
// @i 清理的起始下标位置
// @clen 待清理的片区长度
// @return 新的下标位置
func (c *Clients) forceClean(i, clen int) int {
	end := i + clen
	z := len(c.nodes) - clen

	// 池大小已小于清理长度
	if z <= 0 {
		return i
	}
	// 已超出尾部，末尾新鲜节点移到头部。
	if end > len(c.nodes) {
		z = i
		end = len(c.nodes) - i
		i = 0
	}
	// 末尾新值前移，后段可能有交叠覆盖
	copy(c.nodes[i:end], c.nodes[z:])

	// 如果末尾交叠
	// 覆盖交叠的应为更新鲜的节点，保留。
	if end > z {
		z = end
	}
	c.nodes = c.nodes[:z]

	return end % len(c.nodes)
}

// 活跃性清理。
// 行为类似forceClean，但优先考虑清理段移除（末尾交叠区处理）。
// 清理段长度由时间检查而来，故必然在池内。
// @i 清理的起始下标
// @clen 待清理的片区长度
func (c *Clients) liveClean(i, clen int) int {
	end := i + clen
	z := len(c.nodes) - clen
	lap := 0

	// 如果末尾交叠
	if end > z {
		lap = end - z
		z, end = end, z // 交叠区等待移除，暂不管
	}
	// 末尾新值前移
	copy(c.nodes[i:end], c.nodes[z:])

	// 保证交叠部分移除
	c.nodes = c.nodes[:z-lap]

	return end % len(c.nodes)
}

// 移除一个成员。
// 有一个优化处理以避免末尾新成员移动到最前段。
// 实现：
// 如果目标所在位置太靠前（1/3），会先在中段随机选取一个成员作为中间换位。
// 即取随机位置的成员前移覆盖，然后末尾新节点移动到原随机位置。
// 返回：移除成员后的总成员集
func (c *Clients) deleteOne(node *Client) []*Client {
	i := 0
	var tmp *Client
	list := c.nodes

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

// Clients4 NAT分类节点池组
// [0] - Pub&FullC
// [1] - RC
// [2] - P-RC
// [3] - Sym
type Clients4 [4]*Clients

// ClientsPool 应用节点池组集
// 可包含任意应用类型，每一个类型对应一个按NAT分类的节点池组。
// key: 应用类型名
type ClientsPool map[string]Clients4

// NewClientsPool 创建一个应用节点池组集
func NewClientsPool() ClientsPool {
	return make(map[string]Clients4)
}

// Init 初始化应用池组。
// 每一种应用初始使用时都需要调用该初始化函数。
// 注意：
// 不支持并发安全，因此用户需要在程序最开始时初始化自己支持的所有应用。
// @kind 应用类型名
// @size 池大小限制
// @cleanlen 清理的片段长度
func (cp ClientsPool) Init(kind string, size, cleanlen int) {
	cp[kind] = cp.initClients4(size, cleanlen)
}

// Clients 获取一个应用节点池。
// level:
//   - NAT_LEVEL_NULL
//   - NAT_LEVEL_RC
//   - NAT_LEVEL_PRC
//   - NAT_LEVEL_SYM
//
// @kind 应用类型名
// @level 目标NAT层级（0 ~ 3）
func (cp ClientsPool) Clients(kind string, level NatLevel) *Clients {
	if _, ok := cp[kind]; !ok {
		return nil
	}
	return cp[kind][level]
}

// Supported 是否支持目标类型服务。
func (cp ClientsPool) Supported(kind string) bool {
	if _, ok := cp[kind]; ok {
		return true
	}
	return false
}

// Clean 清理目标类型的应用节点池组
// @kinds 目标应用名称集
// @long 有效期时长
func (cp ClientsPool) Clean(kinds []string, long time.Duration) {
	for _, kind := range kinds {
		cs4, ok := cp[kind]
		if !ok {
			continue
		}
		// 各自独立，可并行清理
		for _, cs := range cs4 {
			go cs.Clean(long)
		}
	}
}

// 初始化创建一个NAT4节点池组
// 注意将指针成员构造为有效的的节点池实例。
func (cp ClientsPool) initClients4(size, clen int) Clients4 {
	return [4]*Clients{
		NewClients(size, clen),
		NewClients(size, clen),
		NewClients(size, clen),
		NewClients(size, clen),
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

// EncodePeers 编码节点数据
// 内部实际上是使用 Peer 的 proto 定义。
// 注记：
// 结果数据中包含了封装切片的父结构 Peers{[]*Peer}。
func EncodePeers(nodes []*Node) ([]byte, error) {
	buf := &Peers{
		Peers: toPeers(nodes),
	}
	return proto.Marshal(buf)
}

// DecodePeers 解码节点数据
// 内部将封装在Peers中的切片数据提取出来。
// 注：data 为 EncodePeers 编码的数据。
func DecodePeers(data []byte) ([]*Node, error) {
	peers := &Peers{}

	if err := proto.Unmarshal(data, peers); err != nil {
		return nil, err
	}
	return toNodes(peers.Peers), nil
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

// EncodeClientUDP 编码客户端UDP信息
// @addr 远端UDP地址
// @sn 标识序列号
func EncodeClientUDP(addr *net.UDPAddr, sn ClientSN) ([]byte, error) {
	its := &ClientUDP{
		Ip:   addr.IP,
		Port: int32(addr.Port),
		Sn32: sn[:],
	}
	return proto.Marshal(its)
}

// DecodeClientUDP 解码客户端UDP编码数据。
func DecodeClientUDP(data []byte) (*net.UDPAddr, ClientSN, error) {
	buf := &ClientUDP{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return nil, ClientSN{}, err
	}
	// 可靠性复检
	if _, ok := netip.AddrFromSlice(buf.Ip); !ok {
		return nil, ClientSN{}, errors.New("parse ip is failed")
	}
	addr := &net.UDPAddr{
		IP:   buf.Ip,
		Port: int(buf.Port),
	}
	return addr, ClientSN(buf.Sn32), nil
}

// 生成不重复随机值序列。
// 用于随机索引值生成，在一个大的切片中随机提取成员。
// @n 生成的数量（序列长度）
// @max 最大整数值的上边界（不含）
func randomIndexs(n, max int) []int {
	nums := make(map[int]bool)
	list := make([]int, n)

	if n > max {
		log.Fatal("Random number amount is too large.")
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

			if err := Online(node, long); err != nil {
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
// @node 目标节点
// @long 拨号等待超时时间，0值采用系统默认值
func Online(node *Node, long time.Duration) error {
	conn, err := WebsocketDial(node.IP, int(node.Port), long)
	if err != nil {
		return err
	}
	// 发送同类问候
	// 需对方回应正确的消息以判断是否同为Findings节点。
	// 因此不是 websocket.PingMessage
	err = conn.WriteMessage(websocket.TextMessage, []byte(config.CmdFindPing))
	if err != nil {
		return err
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if string(msg) != config.CmdFindOK {
		return errOnline
	}
	return nil
}
