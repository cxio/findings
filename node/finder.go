// 作为客户端使用的代码实现
package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/cxio/findings/base"
	"github.com/cxio/findings/config"
	"github.com/cxio/findings/node/pool"
	"github.com/cxio/findings/stun"
	"github.com/cxio/findings/stun/natx"
	"github.com/gorilla/websocket"
)

// Rnd16 密钥因子类型引用
type Rnd16 = natx.Rnd16

// Banner 禁闭查询器。
type Banner struct {
	Addr  string    // IP:Port 字符串
	Reply chan bool // 回复通道（禁闭中：true，未禁闭：false）
}

// 创建一个禁闭查询。
func newBanner(node *Node) *Banner {
	return &Banner{
		Addr:  node.String(),
		Reply: make(chan bool),
	}
}

// Close 关闭查询器。
func (b *Banner) Close() {
	close(b.Reply)
}

var (
	// 禁闭查询通道
	BanQuery = make(chan *Banner)

	// 禁闭添加通道
	// 单向添加，带缓存无阻塞。
	BanAddto = make(chan string, 1)
)

var (
	// 池已为空。
	ErrEmptyPool = errors.New("the pool was empty")

	// 结束通知
	ErrServiceDone = errors.New("service exited successfully")
)

//
// 组网池
//////////////////////////////////////////////////////////////////////////////

// Finder Findings组网节点
// xhost 用于NewHost通知，让本地服务器向对端请求NewHost协作。
type Finder struct {
	*Node                   // TCP 对端节点
	Conn  *websocket.Conn   // 当前 Websocket 连接
	udper *natx.Client      // UDP 探测器
	done  chan struct{}     // 服务结束通知
	xhost chan *stun.Client // NewHost 请求协助通道
}

// NewFinder 新建一个Finder
func NewFinder(node *Node, conn *websocket.Conn, udpc *natx.Client) *Finder {
	return &Finder{
		Node:  node,
		Conn:  conn,
		udper: udpc,
		done:  make(chan struct{}),
		xhost: make(chan *stun.Client, 1),
	}
}

// Server 作为服务器启动（连入）。
// 注：上层退出会自动关闭 f.Conn
// @ctx 当前服务进程上下文
// @notice 本地UDP服务器协助通知通道（NewHost）
func (f *Finder) Server(ctx context.Context, notice chan<- *stun.Notice) {
	// 阻塞，直到断开
	f.serve(ctx, notice)
}

// Client 作为客户端启动（连出）。
// 注：需主动关闭 f.Conn
// @ctx 当前服务进程上下文
// @notice 本地UDP服务器协助通知通道（NewHost）
func (f *Finder) Client(ctx context.Context, notice chan<- *stun.Notice) {
	go func() {
		defer f.Conn.Close()
		f.serve(ctx, notice)
	}()
}

// 对接入的组网连接（Finder节点）提供服务。
// 注记：
// 不含 NAT 探测和打洞协助服务，这由 Applier.Serve 提供。
// @ctx 当前服务进程上下文
// @notice 本地UDP服务器协助通知通道（NewHost）
func (f *Finder) serve(ctx context.Context, notice chan<- *stun.Notice) {
	loger.Printf("A finder listen start [%s]\n", f.Node)
	start := time.Now()
top:
	for {
		select {
		case <-ctx.Done():
			break top
		case <-f.done:
			break top

		// 请求对端执行 NewHost 协作
		case cli := <-f.xhost:
			data, err := hostoData(cli)
			if err != nil {
				loger.Println("[Error]", err)
				break
			}
			if err = f.Conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				loger.Println("[Error]", err)
			}

		default:
			typ, msg, err := f.Conn.ReadMessage()
			if err != nil {
				loger.Println("[Error]", err)
				break top
			}
			switch typ {
			// 简单指令
			case websocket.TextMessage:
				if err := f.simpleProcess(string(msg), f.Conn); err != nil {
					loger.Println("[Error]", err)
					break top
				}
			// 复合指令
			case websocket.BinaryMessage:
				if err := f.process(msg, f.Conn, notice); err != nil {
					loger.Printf("[%s] finder service exited on %s\n", f.Node, err)
					break top
				}
			}
		}
	}
	// 移出组网池
	node := findings.Dispose(f.Conn)
	if node != nil {
		node.Quit()
	}
	// 触发补充检查
	finderReplenish(ctx, findings, shortList, BanAddto)

	loger.Printf("[%s] finder served for %s\n", f.Node, time.Since(start))
}

// 服务：单次处理。
// 根据不同的请求提供相应的组网类服务，
// 不含NAT探测和打洞协助，但配合NAT探测中的对外NewHost请求。
// 仅在需要终止服务时才返回错误。
// @data 读取的数据
// @conn 原websocket连接
// @w 原 http 连接
// @return 终止服务的错误或nil
func (f *Finder) process(data []byte, conn *websocket.Conn, notice chan<- *stun.Notice) error {
	// 顶层解码
	cmd, data, err := base.DecodeProto(data)
	if err != nil {
		return err
	}
	switch cmd {
	// 信息互助
	// 分享彼此自己候选池中的Findings节点信息。
	case base.COMMAND_PEER:
		go func() {
			// 接收：在线测试耗时，独立处理。
			if err := findingsGets(data, shortList, BanQuery); err != nil {
				loger.Println("[Error] get peers from client:", err)
			}
		}()
		nodes := shortList.List(config.SomeFindings)
		if nodes == nil {
			return ErrEmptyPool
		}
		return findingsPush(conn, nodes, cmd)

	// NewHost 配合
	// 接受对端的NewHost请求，向传送来的目标UDP地址发送消息。
	case base.COMMAND_STUN_HOST:
		addr, sn, err := stun.DecodeHosto(data)
		if err != nil {
			loger.Println("[Error] decode Hosto:", err)
			return err
		}
		// 本地UDP服务器协作
		notice <- stun.NewNotice(stun.UDPSEND_NEWHOST, addr, sn)

	// 作为客户端时的逻辑
	// 当外部调用 Finder.NatLevel|.NatLive|.Punching 时接收响应。
	// data: stun.ServInfo
	//----------------------------------------------------------

	// STUN:Cone 主服务
	case base.COMMAND_STUN_CONE:
		// TCP远端仅用于提取IP
		if err := f.setClientInfo(data, conn.RemoteAddr()); err != nil {
			return err
		}
		if err := f.udper.Dial(); err != nil {
			return err
		}
		f.udper.Tester <- natx.STUN_CONE

	// STUN:Sym 副服务
	case base.COMMAND_STUN_SYM:
		if err := f.setClientInfo(data, conn.RemoteAddr()); err != nil {
			return err
		}
		if err = f.udper.Dial(); err != nil {
			return err
		}
		f.udper.Tester <- natx.STUN_SYM

	// NAT 生存期侦测
	// 需要已执行过 STUN:Cone|Sym，此不再拨号。
	case base.COMMAND_STUN_LIVE:
		if !f.udper.Dialled() {
			return natx.ErrNotAddr
		}
		if err := f.setClientInfo(data, conn.RemoteAddr()); err != nil {
			return err
		}
		f.udper.Tester <- natx.STUN_LIVE

	// 取得自己的UDP地址
	case base.COMMAND_PEERUDP:
		addr, err := stun.DecodeUDPInfo(data)
		if err != nil {
			return err
		}
		f.udper.UDPeer <- addr

	// 服务器端收益地址
	case base.COMMAND_STAKE:
		_, stake, err := base.DecodeStake(data)
		if err != nil {
			loger.Println("[Error]", err)
		}
		// 仅打印
		loger.Println("Server stake address:", stake)

	// 容忍：消息不合规，仅打印。
	default:
		loger.Println("[Error]", ErrSendIllegal)
	}
	return nil
}

// 服务：单次简单处理。
// 当对端发送简单的文本消息时，根据消息值的不同作相应处理。
// @msg 请求指令名
// @conn 当前连接
func (f *Finder) simpleProcess(msg string, conn *websocket.Conn) error {
	switch msg {
	// 连接内对端探测
	case base.CmdFindPing:
		if err := conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindOK)); err != nil {
			return err
		}
	// 结束连接
	case base.CmdFindBye:
		return ErrServiceDone
	// 不合规消息
	default:
		return ErrSendIllegal
	}
	return nil
}

// 服务端信息解码，设置到客户端对象上。
// @data 服务端发送的信息
// @addr 服务器IP地址
// @return 半个密钥因子
func (f *Finder) setClientInfo(data []byte, addr net.Addr) error {
	serv, err := stun.DecodeServInfo(data)
	if err != nil {
		return err
	}
	ip, _ := stun.AddrPort(addr)
	// 基本信息
	f.udper.SetInfo(ip, serv)

	return nil
}

// NewHost 请求对端发送一个UDP探测包。
// @peer UDP探测包的接收端
func (f *Finder) NewHost(peer *stun.Client) {
	f.xhost <- peer
}

// NatLevel 请求NAT层级探测服务。
// 作为客户端，向当前TCP连接的对端请求NAT探测服务。
//   - 首先请求 STUN:Cone 主服务，
//   - 视情况决定是否向其它对端请求 STUN:Sym 服务。
//     注：依然是以应用端连出的对端。
//
// 这是一个阻塞的调用，如果未出错，会等到分析出结果才返回。
//
// 使用：
// 初始向对端请求本服务时，需先向服务器声明自己的目的。
// 即 base.Kind.seek 字段设置为 SEEK_APPSERV。
//
//	kind := base.EncodeKind(...)
//	base.EncodeProto(base.COMMAND_KIND, kind)
//
// @return 自身所属的NAT层级
func (f *Finder) NatLevel() (NatLevel, error) {
	// STUN:Cone
	err := f.Conn.WriteMessage(websocket.TextMessage, []byte(base.CmdStunCone))
	if err != nil {
		return NAT_LEVEL_ERROR, err
	}
	loger.Printf("Send STUN:Cone request [%s].\n", f.Node)

	// 若成功
	if lev := <-f.udper.LevCone; lev < NAT_LEVEL_PRCSYM {
		return lev, nil
	}

	// 向另一个对端请求 STUN:Sym
	node := findings.Other(f)
	if node == nil {
		return NAT_LEVEL_ERROR, ErrEmptyPool
	}
	return node.natLevel(f.udper.PubAddr())
}

// 请求对端的 STUN:Sym 服务。
// 这是向连接池中另一个节点请求服务，避免IP相同。
// 也即：
// 本Finder与调用者不是同一个连接对。
//
// @src 请求者自己获取的UDP地址（STUN:Cone）
func (f *Finder) natLevel(src *net.UDPAddr) (NatLevel, error) {
	// STUN:Sym
	err := f.Conn.WriteMessage(websocket.TextMessage, []byte(base.CmdStunSym))
	if err != nil {
		return NAT_LEVEL_ERROR, err
	}
	f.udper.SetCmpAddr(src)
	loger.Printf("Send STUN:Sym request [%s].\n", f.Node)

	return <-f.udper.LevSym, nil
}

// NatLive 请求NAT生存期探测服务。
// 作为客户端，向当前连接的对端请求NAT生存期探测。
// 用户通常应当多调用几次本方法，来推算出一个恰当的值。
// 注意：同上 NatLevel 说明。
// @return NAT生命周期（-1表示出错）
func (f *Finder) NatLive() (time.Duration, error) {
	// STUN:Live
	err := f.Conn.WriteMessage(websocket.TextMessage, []byte(base.CmdStunLive))
	if err != nil {
		return -1, err
	}
	loger.Printf("Send STUN:Live request [%s].\n", f.Node)

	return <-f.udper.Live, nil
}

// Punching 请求打洞协助。
// 作为客户端，向当前TCP连接的对端请求打洞协助。
// @peer 自身关联的UDP节点信息
func (f *Finder) Punching(peer *LinkPeer) error {
	// 方向由服务器决定
	info, err := stun.EncodePunch("", peer)
	if err != nil {
		return err
	}
	// 注意：非.COMMAND_PUNCHX
	data, err := base.EncodeProto(base.COMMAND_PUNCH, info)
	if err != nil {
		return err
	}
	// 发送封装包
	return f.Conn.WriteMessage(websocket.BinaryMessage, data)
}

// Quit 节点退出。
// 关闭通道，服务进程会退出后自动关闭 f.Conn。
func (f *Finder) Quit() {
	close(f.done)
	close(f.xhost)
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

// Dispose 清除目标连接节点。
// @conn 目标连接
// @return 被移除的目标节点
func (f *Finders) Dispose(conn *websocket.Conn) *Finder {
	test := func(node *Finder) bool {
		return conn == node.Conn
	}
	return pool.Dispose(&f.pool, test)
}

// Get 引用一个随机成员。
func (f *Finders) Get() *Finder {
	return pool.Get(&f.pool)
}

// Other 获取一个不同于old的节点。
func (f *Finders) Other(old *Finder) *Finder {
	max := pool.Size(&f.pool)

	for i := 0; i < max; i++ {
		node := pool.Get(&f.pool)
		if node != old {
			return node
		}
	}
	return nil
}

// Take 提取一个随机成员。
func (f *Finders) Take() *Finder {
	return pool.Take(&f.pool)
}

// List 应用多个随机成员。
func (f *Finders) List(count int) []*Finder {
	return pool.List(&f.pool, count)
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
// 服务辅助
//////////////////////////////////////////////////////////////////////////////

// 获取对端发送的节点集信息。
// 解码对端的数据，检查测试节点集成员的在线情况，然后汇入候选池。
// @conn 当前连接
// @pool 有效节点汇入池（候选池）
// @qban 禁闭查询通道
func findingsGets(data []byte, pool *Shortlist, qban chan *Banner) error {
	nodes, err := DecodePeers(data)
	if err != nil {
		return err
	}
	// 排除被禁闭的
	nodes = filterBanned(nodes, qban)

	if len(nodes) > 0 {
		// 仅在线的节点入池。
		pool.Adds(Onlines(nodes, 0)...)
	}
	// 合并后再去重
	n := pool.Unique()
	if n > 0 {
		loger.Printf("There are %d duplicates in pool.\n", n)
	}
	return nil
}

// 发送节点集信息。
// 注意list节点集可能为空，这将会发送一个空集。
// @conn 当前连接
// @pool 节点提取来源池（候选池）
// @max 提取节点的最大数量
func findingsPush(conn *websocket.Conn, list []*Node, cmd base.Command) error {
	data, err := EncodePeers(list)
	if err != nil {
		loger.Println("[Error] encoding findings peers.")
		return err
	}
	data, err = base.EncodeProto(cmd, data)
	if err != nil {
		loger.Println("[Error] encoding protodata.")
		return err
	}
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		loger.Println("[Error] send peers message.")
		return err
	}
	return nil
}

// 组网池成员补充至满员。
// 从候选池中取出节点，直到找到一个在线的对端。
// @ctx 控制上下文
// @pool 组网池
// @list 候选池
// @aban 添加禁闭地址的通道
func finderReplenish(ctx context.Context, pool *Finders, list *Shortlist, aban chan<- string) {
	loger.Println("Replenish the finder pool...")
	start := time.Now()

	for {
		if pool.IsFulled() {
			break
		}
		new, err := createFinder(list)
		if err != nil {
			loger.Println("[Error] create finder:", err)
			break
		}
		if err = finderShare(new, list, aban); err != nil {
			loger.Println("[Error] finder share peers:", err)
			continue
		}
		if err = pool.Add(new); err != nil {
			loger.Println("[Error] add applier into pool:", err)
			break
		}
		new.Client(ctx, stunNotice)
	}

	loger.Println("Replenish finder pool done took", time.Since(start))
}

// 组网池成员信息分享
// - 向对端发送分享指令及其数据。
// - 接收对端回应的分享数据。
// @finder 组网节点
// @list 分享来源（候选池）
// @aban 添加禁闭地址的通道
func finderShare(finder *Finder, list *Shortlist, aban chan<- string) error {
	var err error
	// 分享节点信息
	nodes := list.List(config.SomeFindings)
	if nodes == nil {
		return ErrEmptyPool
	}
	if err = findingsPush(finder.Conn, nodes, base.COMMAND_PEER); err != nil {
		return err
	}
	// 接收分享回馈
	if err = receivePeers(finder.Conn, list, base.COMMAND_PEER); err != nil {
		loger.Println("[Error] receive shared peers.")
		// 加入黑名单
		// 理由：在线且可正常接收数据，但无法提供正常的服务。
		node := NewWithAddr(
			finder.Conn.RemoteAddr())
		aban <- node.String()
	}
	return err
}

// 接收对端分享的节点信息。
// 此为客户端向服务器发送请求信息指令后，接收对端的数据。
// @conn 目标连接
// @pool 待汇入目标（候选池）
// @cmdx 欲匹配的消息指令
func receivePeers(conn *websocket.Conn, pool *Shortlist, cmdx base.Command) error {
	typ, msg, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if typ != websocket.BinaryMessage {
		return errors.New("receive shared peers datatype invalid")
	}
	cmd, data, err := base.DecodeProto(msg)

	if err != nil {
		return err
	}
	if cmd != cmdx {
		return errors.New("decoded protodata command is invalid")
	}
	return findingsGets(data, pool, BanQuery)
}

//
// 工具函数
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

			if err := node.Online(long); err != nil {
				node.Ping = -1
				loger.Printf("[%s] is unreachable because %s\n", node, err)
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

// 提取候选池成员创建一个Finder
// 会持续从候选池中提取节点，直到目标节点可用。
// @pool 节点取用源（候选池）
func createFinder(pool *Shortlist) (*Finder, error) {
	for {
		its := pool.Take()
		if its == nil {
			return nil, ErrEmptyPool
		}
		conn, err := WebsocketDial(its.IP, its.Port, 0)

		if err != nil {
			loger.Println("[Error] shortlist node was offline:", err)
			continue
		}
		// 注记：
		// 此时Finder是充当组网节点还是应用节点并未确定。
		// 这由向对端写入的首个消息决定。
		return NewFinder(its, conn, clientUDP), nil
	}
}

// 禁闭节点过滤
// @nodes 原节点集
// @qban 禁闭查询通道
// @return 未禁闭的节点集
func filterBanned(nodes []*Node, qban chan *Banner) []*Node {
	buf := make([]*Node, 0, len(nodes))

	for _, node := range nodes {
		bq := newBanner(node)
		qban <- bq

		if <-bq.Reply {
			loger.Println("[Warning] The banned node: ", bq.Addr)
			continue
		}
		buf = append(buf, node)
	}
	return buf
}

// 编码NewHost请求的数据。
func hostoData(cli *stun.Client) ([]byte, error) {
	// 消息编码
	data, err := stun.EncodeHosto(cli.Addr, cli.SN)
	if err != nil {
		return nil, err
	}
	return base.EncodeProto(base.COMMAND_STUN_HOST, data)
}
