// 节点模块
// 包含Findings候选池、连接池以及应用节点池的支持。
package node

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/cxio/findings/base"
	"github.com/cxio/findings/config"
	"github.com/cxio/findings/node/pool"
	"github.com/cxio/findings/stun"
	"github.com/cxio/findings/stun/natx"
	"github.com/gorilla/websocket"
)

var (
	// 对端不在线
	ErrOnline = errors.New("the target node is offline")

	// 发送了错误的消息
	ErrSendIllegal = errors.New("the client sent an illegal message")

	// 消息格式错误
	ErrMsgFormat = errors.New("invalid message format")

	// 不支持目标类型应用
	ErrAppKind = errors.New("not support the kind of application")
)

const (
	cleanSize      = 10               // 分享池单次清理量
	defaultTimeout = time.Second * 30 // 默认超时时间
)

// 私有全局变量
var (
	// 用户配置
	cfgUser *config.Config

	// 候选池
	shortList *Shortlist

	// 组网池
	findings *Finders

	// 应用端节点池集
	applPools AppliersPool

	// TCP 分享池集
	tcpStores TCPStorePool

	// UDP 客户端
	clientUDP *natx.Client

	// NAT 探测协作通知渠道
	// 本地TCP服务器与本地UDP服务器之间的通讯通道。
	stunNotice = make(chan *stun.Notice, 1)

	// NAT 探测客户端信息通道
	// 由本地UDP服务器解析对端UDP地址后，转发至TCP服务器的通道。
	stunClient <-chan *stun.Client

	// 服务器权益地址池
	// - key: 应用类型名
	// - value: 接收捐赠的区块链账户地址
	stakePool map[string]string

	// 提供的服务名集
	// 注：其中的 Seek 字段无用（忽略）。
	serviceKinds []*base.Kind
)

// Init 模块初始化。
// 根据传入的配置，初始化一些全局变量，启动部分内置全局服务。
// @ctx 全局上下文
// @cfg 用户配置集
// @stake 支持的“服务:权益地址”集
// @chpeer 广域搜索节点递送通道
// @done 广域搜索终止通知
func Init(ctx context.Context, cfg *config.Config, stake map[string]string, chpeer <-chan *config.Peer, done chan<- struct{}) {
	cfgUser = cfg
	findings = NewFinders(cfg.Findings)
	shortList = NewShortlist(cfg.Shortlist)
	tcpStores = NewTCPStorePool()

	// STUN:Live 服务
	// 如果节点在NAT内部，通常无需启动该服务。
	if cfg.STUNLiving {
		go stun.LiveListen(ctx, cfg.UDPLiving, base.GlobalSeed)
	}
	// STUN:NAT 探测服务
	// 普通非公网Findings节点也可配合执行NewHost发送。
	stunClient = stun.ListenUDP(ctx, cfg.UDPListen, base.GlobalSeed, stunNotice)

	// 作为NAT受限客户端
	// - 需要探测自身NAT层级以及NAT生存期。
	// - 需要UDP打洞连接其它Finder节点增强交互。
	if cfg.STUNClient {
		client, err := natx.ListenUDP(ctx)
		if err != nil {
			log.Fatalln("Create Client:UDP failed on", err)
		}
		clientUDP = client
	}

	// 服务:权益地址
	stakePool = stake
	serviceKinds = serviceList(stake)

	// 应用支持
	applPools = NewAppliersPool()
	names := serviceNames(serviceKinds)

	for _, kn := range names {
		applPools.Init(kn, cfg.ConnApps)
		tcpStores.Init(kn, cfg.ConnApps, cleanSize)
	}
	// 应用池清理巡查
	if applPools.Size() > 0 {
		go serverPatrol(ctx, applPools, config.ApplierPatrol, names)
	}

	// 接收广域 Finder
	go serverPeers(ctx, chpeer, done, findings, shortList)

	// 候选池在线巡查
	go serverShortlist(ctx, shortList, config.ShortlistPatrol)

	// Finder组网巡查
	go serverFinders(ctx, findings, shortList, config.FinderPatrol)
}

// ProcessOnKind 相应类型处理器。
// 根据客户端发送的声明信息，提供相应的服务。
// 顶层有4个服务：
// - SEEK_ASSISTX 上线协助，提供初始上线的节点一些Findings服务器。
// - SEEK_KINDAPP 支持的应用类型探查。方便应用端广域搜寻同类应用端。
// - SEEK_FINDNET Finder组网。应当是一个Findings节点请求连入。
// - SEEK_APPSERV 应用端寻求服务：NAT 探测或 UDP 打洞协助。
// - SEEK_PEERTCP 应用登记自己传递的节点为TCP服务器（同应用类型）。
// @kind 应用端声明
// @conn 当前TCP连接
// @w 原始http写入器
func ProcessOnKind(kind *base.Kind, conn *websocket.Conn, w http.ResponseWriter) {
	// 当前处理上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 对端信息
	node := NewWithAddr(conn.RemoteAddr())
	if node == nil {
		log.Println("[Error] unknown remote addr type.")
		return
	}
	switch kind.Seek {
	// 上线协助（any）
	// 通常为本地局域Findings节点的第一个请求。
	case base.SEEK_ASSISTX:
		list := shortList.List(cfgUser.PeersHelp)
		// 如果候选池为空，没有回复。
		if list == nil {
			log.Println("[Error]", ErrEmptyPool)
			break
		}
		// 推送一些Findings节点。
		if err := findingsPush(conn, list, base.COMMAND_HELP); err != nil {
			log.Println("Error", err)
			http.Error(w, "Some internal errors", http.StatusInternalServerError)
		}

	// 应用名清单（any）
	// 在上线协助获取一定Finder之后，用于广域寻求同类节点。
	// 原因：
	// 用户需要首先知道哪些Finder支持自己所属的应用。
	case base.SEEK_KINDAPP:
		if err := findingsKinds(conn, serviceKinds, base.COMMAND_KINDLIST); err != nil {
			log.Println("[Error] put service kinds:", err)
		}

	// only findings
	// 组网类接入
	case base.SEEK_FINDNET:
		if findings.IsFulled() {
			http.Error(w, "Too many connections", http.StatusTooManyRequests)
			log.Printf("Finder pool is fulled when [%s] join.\n", conn.RemoteAddr())
			break
		}
		finder := NewFinder(node, conn, clientUDP)

		if err := findings.Add(finder); err != nil {
			log.Println("[Error] Add finder into pool but", err)
			break
		}
		// 阻塞：向当前组网节点提供服务
		finder.Server(ctx, stunNotice)

	// depots|blockchain|app|findings
	// 应用服务：NAT探测&打洞服务
	case base.SEEK_APPSERV:
		if applPools.Size() == 0 {
			http.Error(w, "not support your applier.", http.StatusForbidden)
			break
		}
		kname := base.KindName(kind.Base, kind.Name)

		// 递送相应类型权益地址
		// 对于请求应用服务的客户端来说，这是第一个发送的消息（如果有）。
		stake := serviceStake(kname)
		if stake != "" {
			if err := writeStake(conn, config.User, stake); err != nil {
				log.Println("[Error]", err)
				break
			}
		}
		// 注记：
		// 当应用节点请求打洞时才添加到池。
		// 此时对端已经探知了自己的 NAT 类型和 UDP 地址。
		app := NewApplier(node, kname, conn)

		// 阻塞：提供服务
		app.Server(ctx, stunNotice, stunClient)

	// 登记TCP服务器
	// 用于第三方应用端获得自己同类的可直连服务器。
	// 注记：
	// 登记TCP服务器的对端必须位于公网或可被直连，无需NAT探测或打洞服务。
	// 因此这里为完成后结束。
	case base.SEEK_PEERTCP:
		store, err := tcpStores.TCPStore(base.KindName(kind.Base, kind.Name))
		if err != nil {
			log.Println("[Error]", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			break
		}
		if err = registerTCPStore(conn, store); err != nil {
			log.Println("[Error]", err)
			conn.WriteMessage(websocket.TextMessage, []byte(err.Error()))
		}

	default:
		log.Println(ErrSendIllegal)
		http.Error(w, "unknown seed type.", http.StatusBadRequest)
	}
}

//
// 通用节点
//////////////////////////////////////////////////////////////////////////////

// Node 在线节点
// 记录节点的基本信息，可用于当前连接节点或待创建连接的节点。
type Node struct {
	IP    netip.Addr    // 对端 IP
	Port  int           // 监听/通讯端口
	Start time.Time     // 加入时间
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
	ip, port := stun.AddrPort(addr)
	return &Node{IP: ip, Port: port, Start: time.Now()}
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

// Hello 节点问候
// 探知对端是否有反应（可连接）。
// 仅针对TCP基础链路，采用普通TCP连接协议即可。
// @long 测试超时时间
func (n *Node) Hello(long time.Duration) bool {
	// IPv6 | IPv4
	ipp := netip.AddrPortFrom(n.IP, uint16(n.Port))

	conn, err := net.DialTimeout("tcp", ipp.String(), long)
	if err != nil {
		fmt.Printf("Unable to connect to %s: %s\n", ipp, err)
		return false
	}
	defer conn.Close()

	log.Printf("Successfully connected to %s\n", ipp)
	return true
}

// Online 测试对端是否在线。
// 拨号测试对端是否为本类服务节点（Findings）。
// 如果返回错误，表示对端无法连通或不是同类节点。
// @long 拨号等待时间
func (n *Node) Online(long time.Duration) error {
	conn, err := WebsocketDial(n.IP, n.Port, long)
	if err != nil {
		return err
	}
	defer conn.Close()
	start := time.Now()

	// 同类问询：
	// 非 websocket.PingMessage
	err = conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindPing))
	if err != nil {
		return err
	}
	if long <= 0 {
		long = defaultTimeout
	}
	conn.SetReadDeadline(time.Now().Add(long))

	_, msg, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	// 对端需回应正确的消息。
	if string(msg) != base.CmdFindOK {
		return ErrOnline
	}
	n.Start = start
	n.Ping = time.Since(start)

	return nil
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

// Take 提取一个随机成员。
func (s *Shortlist) Take() *Node {
	return pool.Take(&s.pool)
}

// Takes 提取一些随机成员。
func (s *Shortlist) Takes(count int) []*Node {
	return pool.Takes(&s.pool, count)
}

// List 获取一个随机节点集。
// 返回集可能不足count的数量，如果池中成员不足的话。
// @count 获取数量
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
	test := func(node *Node) bool {
		return node.Online(-1) != nil
	}
	start := time.Now()
	out := pool.Clean(ctx, &s.pool, test)

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
// 分享池
// ---------------------------------------------------------------------------
// 汇聚各类应用的TCP服务器的信息。
// 注意：
// 分享池成员的登记是开放式的自由登记，没有验证。
// 因此任何节点都可能冒充某应用类型的TCP服务器，而这可能是恶意的。
//
// 获取服务器节点信息的客户端有必要自行验证所获得的服务器是否有效或安全。
// 这里仅能通过无条件更新的方式，避免恶意节点长期霸占。
// 或许就像维基百科，
// 这里需要正常服务器节点的日常性登记更新（hour）。
//////////////////////////////////////////////////////////////////////////////

// TCPStore 应用服务器库
// Node存储的是对端提供的TCP服务器的节点信息。
// 采用快速更新的策略：
// - 池满即将末尾部分移动到清理游标处。
// 因此要求池容量大小是单次清理长度的整数倍。
type TCPStore struct {
	queue   []*Node    // 节点池
	maxSize int        // 池容量
	count   int        // 单次清理数量
	cursor  int        // 清理游标
	mu      sync.Mutex // 同步锁
}

// NewTCPStore 新建一个分享池。
// 池大小应当是单次清理量的整数倍，否则会自动转为整数倍。
// 池大小至少应当是清理量大小的两倍。
// @size 池大小限制
// @count 单次清理大小
func NewTCPStore(size, count int) *TCPStore {
	// 整数倍
	if size%count != 0 {
		size = (size/count + 1) * count
	}
	return &TCPStore{
		queue:   make([]*Node, 0, size),
		maxSize: size,
		count:   count,
	}
}

// Add 添加一个节点。
// 如果池满，会触发自动清理操作，因此添加总会成功。
// @return nil
func (t *TCPStore) Add(node *Node) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.queue) == t.maxSize {
		t.cleanFulled()
	}
	t.queue = append(t.queue, node)
	return nil
}

// List 获取一个节点清单
// 如果池中成员不足count的数量，返回全部成员。
// 返回集成员是随机的。
func (t *TCPStore) List(count int) []*Node {
	t.mu.Lock()
	defer t.mu.Unlock()

	sz := len(t.queue)
	if sz == 0 || count == 0 {
		return nil
	}
	ii := pool.Indexes(sz, count)
	list := make([]*Node, len(ii))

	for i, x := range ii {
		list[i] = t.queue[x]
	}
	return list
}

// 池满清理。
// 被清理掉的成员没有资源占用，因此不用返回它们。
// 注意！仅在池满时使用。
func (t *TCPStore) cleanFulled() {
	if len(t.queue) != t.maxSize {
		log.Fatalln("TCPStore not fulled.")
	}
	end := t.maxSize - t.count

	// 片段移动可保留时序性。
	copy(t.queue[t.cursor:], t.queue[end:])
	t.queue = t.queue[:end]

	t.cursor = (t.cursor + t.count) % t.maxSize
}

// TCPStorePool 各类TCP分享池集
// key: (kind:name)
type TCPStorePool map[string]*TCPStore

// NewTCPStorePool 新建一个分享池集。
func NewTCPStorePool() TCPStorePool {
	return make(map[string]*TCPStore)
}

// Init 初始化各类型分享池。
// @kind 应用类型名（kind:name）
// @size 分享池大小
// @count 单次清理长度
func (tp TCPStorePool) Init(kind string, size, count int) {
	tp[kind] = NewTCPStore(size, count)
}

// TCPStore 获取目标类型的TCP分享池
func (tp TCPStorePool) TCPStore(kind string) (*TCPStore, error) {
	ts, ok := tp[kind]
	if !ok {
		return nil, ErrAppKind
	}
	return ts, nil
}

// Supported 是否支持目标类型
func (tp TCPStorePool) Supported(kind string) bool {
	if _, ok := tp[kind]; ok {
		return true
	}
	return false
}

//
// 内置服务
//////////////////////////////////////////////////////////////////////////////

// 初始节点搜寻处理服务
// 从 chin 接收 ips.Finding 找到的有效节点，创建连接并请求上线协助。
// 接收上线协助收到的节点信息，测试节点在线情况、汇入候选池。
// 当组网池满之后，通知 ips.Finding 搜寻结束，本服务也完成初始构造任务。
// @ctx 全局上下文
// @chin 外部节点搜寻服务递送通道
// @done 搜寻结束通知
// @pool 组网池
// @list 候选池
func serverPeers(ctx context.Context, chin <-chan *config.Peer, done chan<- struct{}, pool *Finders, list *Shortlist) {
	log.Println("First peers help server start.")
	defer close(done)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case peer := <-chin:
			if pool.IsFulled() {
				break loop
			}
			if err := findingsHelp(peer, -1, list, BanAddto); err != nil {
				log.Printf("[Error] first help from [%s] failed on %s.", peer, err)
			}
			// 触发组网池补充操作。
			go finderReplenish(ctx, pool, list, BanAddto)
		}
	}
	log.Println("First peers help server exited.")
}

// 候选池巡查服务。
// 主要执行候选池节点的在线检查，清理已下线节点。
// @ctx 当前上下文
// @list 候选池
// @dur 巡查时间间隔（完成->开始）
func serverShortlist(ctx context.Context, list *Shortlist, dur time.Duration) {
	log.Println("Start shortlist online patrol server.")
	// 友好：
	// 初始可能并没有多少节点入池。
	time.Sleep(time.Minute * 20)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case <-time.After(dur):
			list.Clean(ctx)
		}
	}
	log.Println("Shortlist patrol server exited.")
}

// Finder巡查服务
// 定时检查组网池和候选池节点情况：
// - 如果连接池成员充足，随机更新一个连接。
// - 如果连接池成员不足，从候选池提取随机成员补充至满员。
// - 随机对1个连接池成员分享节点信息（COMMAND_PEER）。
// 注记：
// 节点间交换信息融入候选池时，会先检查交换的节点的在线情况。
// 从候选池取出节点补充组网池连接时，也会再测试一次对端是否在线。
// 因此候选池不再设计单独的定时在线检查服务。
// @ctx 当前上下文
// @pool 待监测的组网池
// @list 候选池（备用节点）
// @dur 巡查时间间隔（完成->开始）
func serverFinders(ctx context.Context, pool *Finders, list *Shortlist, dur time.Duration) {
	log.Println("Start finders patrol server.")
	// 友好：
	// 初始可能并没有多少节点入池。
	time.Sleep(time.Minute * 20)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case <-time.After(dur):
			// 随机一成员分享
			// 分享出错会简单忽略，打印出错消息后续继续。
			if its := pool.Get(); its != nil {
				if err := finderShare(its, list, BanAddto); err != nil {
					log.Println("[Error] Finder share peers failed:", err)
				}
			}
			// 更新|补足（隐含分享）
			if pool.IsFulled() {
				finderUpdate(pool, list, BanAddto)
				break
			}
			finderReplenish(ctx, pool, list, BanAddto)
		}
	}
	log.Println("Finders patrol server exited.")
}

// 应用端连接池巡查服务
// 定时检查节点接入时间是否超期或是否在线，移除获取空间。
// @ctx 当前上下文传递
// @pool 应用节点连接池
// @dur 巡查间隔时间（上次巡查完到本次开始）
func serverPatrol(ctx context.Context, pools AppliersPool, dur time.Duration, kinds []string) {
	log.Println("Start client pools patrol server.")
	// 友好：
	// 初始可能并没有多少节点入池。
	time.Sleep(time.Minute * 30)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case <-time.After(dur):
			pools.Clean(ctx, kinds, config.ApplierExpired)
		}
	}
	log.Println("applier pools patrol server exit.")
}

//
// 服务辅助
//////////////////////////////////////////////////////////////////////////////

// 发送服务类型名集
func findingsKinds(conn *websocket.Conn, list []*base.Kind, cmd base.Command) error {
	data, err := base.EncodeServKinds(list)
	if err != nil {
		log.Println("[Error] encoding service kinds.")
		return err
	}
	data, err = base.EncodeProto(cmd, data)
	if err != nil {
		log.Println("[Error] encoding protodata.")
		return err
	}
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		log.Println("[Error] send service kinds message.")
		return err
	}
	return nil
}

// 作为客户端：
// 初始上线请求协助、接收信息并处理。
// - 向目标节点发送上线协助请求，然后接收对端的回应。
// - 回应的节点信息（在线探测后）会汇入到候选池。
// @peer 目标节点
// @long 拨号等待超时设置
// @pool 汇入的节点池（候选池）
// @aban 添加禁闭地址的通道
func findingsHelp(peer *config.Peer, long time.Duration, pool *Shortlist, aban chan<- string) error {
	if pool.IsFulled() {
		return nil
	}
	conn, err := WebsocketDial(peer.IP, int(peer.Port), long)
	if err != nil {
		return err
	}
	// 请求协助编码
	data, err := base.EncodeKind(config.Kind, config.AppName, base.SEEK_ASSISTX)
	if err != nil {
		return err
	}
	// 顶层传送编码
	data, err = base.EncodeProto(base.COMMAND_KIND, data)
	if err != nil {
		return err
	}
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return err
	}
	// 接收协助
	// 不提供正确协助的对端被加入黑名单。
	if err = receivePeers(conn, pool, base.COMMAND_HELP); err != nil {
		aban <- conn.RemoteAddr().String()
		return err
	}
	return nil
}

// 组网池成员更新。
// 从候选池提取一个在线成员创建连接，
// 如果成功，则替换组网池内的一个随机成员。
// 注意：
// 不检查组网池成员是否已满。
// 会即时发送组网消息，交换分享彼此候选池的部分节点信息。
// @pool 组网池
// @list 候选池
// @aban 禁闭添加通道
// @return 更新是否出错
func finderUpdate(pool *Finders, list *Shortlist, aban chan<- string) error {
	var new *Finder
	var err error
	for {
		new, err = createFinder(list)
		if err != nil {
			log.Println("[Error] create finder.")
			return err
		}
		if err = finderShare(new, list, aban); err != nil {
			log.Println("[Error] finder first share peers.")
			continue
		}
		break
	}
	// 先随机移除
	del := pool.Take()
	if del != nil {
		del.Conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindBye))
		del.Conn.Close()
	}
	return pool.Add(new)
}

// 向对端发送收益地址信息。
func writeStake(conn *websocket.Conn, id, stake string) error {
	data, err := base.EncodeStake(id, stake)
	if err != nil {
		return err
	}
	data, err = base.EncodeProto(base.COMMAND_STAKE, data)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// 注册TCP分享池节点。
// 读取对端传来的服务器节点信息，构造节点存储。
// 注记：
// 仅执行简单的在线测试，无法验证。
func registerTCPStore(conn *websocket.Conn, store *TCPStore) error {
	typ, data, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if typ != websocket.BinaryMessage {
		return ErrMsgFormat
	}
	tnode, err := DecodePeer(data)
	if err == nil {
		return err
	}
	// 仅探知是否可连接
	if !tnode.Hello(defaultTimeout) {
		return ErrOnline
	}
	return store.Add(tnode)
}

// 返回提供的服务类型名称集。
// 不符合格式（kind:name）的名称会被简单忽略。
// @stake 服务器权益地址集
func serviceList(stake map[string]string) []*base.Kind {
	list := make([]*base.Kind, 0, len(stake))

	for name := range stake {
		// kind:name
		kn, err := base.Name2Kind(name, "")

		if err != nil {
			log.Println("[Error] parse kind on", err)
			continue
		}
		list = append(list, kn)
	}
	return list
}

// 创建服务类型名称集。
// 将 base.Kind 的分解形式合成为 kind:name 字符串。
func serviceNames(list []*base.Kind) []string {
	names := make([]string, len(list))

	for i, kn := range list {
		names[i] = base.KindName(kn.Base, kn.Name)
	}
	return names
}

// 查询服务类型的受益账号。
// @name 应用服务的类型名
// @return 服务器相应的收益地址（区块链账号）
func serviceStake(name string) string {
	return stakePool[name]
}
