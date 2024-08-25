// 节点发现服务主程序。
// 节点相互连接构建为一个P2P网络，向应用类节点提供其同类节点的信息，
// 同时也提供NAT类型侦测和STUN打洞服务。
//
// 候选池：
// -------
// 可直接连通，仅限于可直接连接的（Pub/FullC）公网类节点。
// 候选池里的公网节点是节点信息交换的目标。
// 组网池的节点会不定时更新，更新时会与新节点交换节点信息。这些信息会合并进入候选池。
// 如果组网池成员不足，也会从候选池中提取成员创建新的连接。
//
// 组网池：
// -------
// 公网节点的当前连接池，仅支持TCP连接。
// 池成员可能为其它公网类节点，也可能是受限节点，取决于连入的请求类型。
// 当前节点除了提供基本的公网节点信息交换外，也提供STUN服务，可能需要池成员的配合。
//
// 受限连接池：
// -----------
// 受限节点的当前连接池，支持对外连出的TCP连接，以及通过UDP打洞服务获得的UDP连接。
// TCP连出通常仅为了获取公网节点信息，以构建自己的公网节点清单。
// TCP与UDP连接数量各占一半。
//
// 节点信息：
// ---------
// - 应用类型：depots:[name] | blockchain:[name] | app:[name] | findings
// - 连接协议：tcp | udp
// - NAT 类型：Pub | FullC | RC | P-RC | Sym
// - 公网地址：[IP]:[Port]
// - 加密公钥：公钥:算法
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/cxio/findings/config"
	"github.com/cxio/findings/crypto/selfsign"
	"github.com/cxio/findings/ips"
	"github.com/cxio/findings/node"
	"github.com/cxio/findings/stun"
	"github.com/gorilla/websocket"
)

// websocket 升级器
var upgrader = websocket.Upgrader{
	ReadBufferSize:  config.BufferSize,
	WriteBufferSize: config.BufferSize,
}

// 服务器权益地址池
// - key: 应用类型名
// - value: 接收捐赠的区块链账户地址
// 只读，并发安全。
var stakePool map[string]string

var (
	// 候选池
	shortList *node.Pool

	// 组网池
	findings *node.Finders

	// 应用端节点池集
	clientPools node.ClientsPool

	// 禁闭查询通道
	// 无缓存，维持不同请求间并发安全。
	banQuery = make(chan string)

	// 禁闭添加通道
	// 单向添加用途，故带缓存无阻塞。
	banAddto = make(chan string, 1)

	// 服务器关闭等待
	idleConnsClosed = make(chan struct{})
)

func main() {
	// 读取基础配置
	cfg, err := config.Base()
	if err != nil {
		log.Fatal("Error reading base config:", err)
	}
	if cfg.BufferSize > 0 {
		upgrader.ReadBufferSize = cfg.BufferSize
		upgrader.WriteBufferSize = cfg.BufferSize
	}

	// 读取可用节点配置
	peers, err := config.Peers()
	if err != nil {
		log.Fatal("Error reading peers config:", err)
	}
	// 恶意节点清单
	bans, err := config.Bans()
	if err != nil {
		log.Fatal("Error reading ban list:", err)
	}

	// 服务器权益账户
	// 注意：赋值到全局变量上。
	stakePool, err = config.Services()
	if err != nil {
		log.Fatal("Error reading stakes of server:", err)
	}

	// 全局节点池
	shortList = node.NewPool(cfg.Shortlist)
	findings = node.NewFinders(cfg.Findings)
	clientPools = node.NewClientsPool()

	// 应用集支持
	for _, kind := range serviceList() {
		// 大小和长度参数暂为统一
		// 此为逐个设置，必要时可为每种应用配置不同的限额。
		clientPools.Init(kind, cfg.ConnApps, config.AppCleanLen)
	}

	// 上下文环境
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 恶意节点监察
	go serverBans(ctx, bans)

	// 应用清理巡查
	// 主要用于不忙的应用清理太旧的信息以节省系统内容。
	go serverPatrol(ctx, clientPools, config.ClientPatrol)

	// 初始节点探测递送通道
	// 通道两端皆为耗时操作，给与缓存自适应。
	chpeer := make(chan *config.Peer, 1)

	// 初始节点探测结束通知
	chdone := make(chan struct{})

	// 向外寻找 Finder
	go ips.Finding(ctx, cfg.RemotePort, peers, cfg.PeerFindRange, chpeer, chdone)

	// 接收寻找到的 Finder.Conn
	go serverPeers(ctx, chpeer, chdone, findings, shortList)

	// Finder巡查服务
	go serverFinders(ctx, findings, shortList, config.FinderPatrol)

	// 启动服务主进程
	serviceListen(cfg.ServerPort)

	log.Println("Findings service EXIT.")
}

//
// 服务器部
//-----------------------------------------------------------------------------
//

// 启动主服务（监听）
// 将创建TLS/SSL连接，但采用即时生成的自签名证书，因为P2P节点无需身份。
// 对端节点应当忽略证书验证（InsecureSkipVerify: true）。
func serviceListen(port int) {
	cert, err := selfsign.GenerateSelfSigned25519()
	if err != nil {
		log.Fatal("Failed to generate self-signed certificate: ", err)
	}
	// 创建TLS配置
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	// WebSocket处理器
	// 监听根目录，可兼容/ws子目录
	http.HandleFunc("/", handleConnect)

	// 创建HTTP服务器
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: config,
	}
	log.Println("Server is running on port", port)

	// 用户中断监听，友好关闭
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		// 关闭提示...
		go func() {
			log.Print("Shutting down the server")
			for {
				fmt.Print(".")
				<-time.After(time.Second)
			}
		}()
		if err := server.Shutdown(context.TODO()); err != nil {
			log.Printf("Error server shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()
	// 启动服务器
	if err = server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatal("Error starting server:", err)
	}

	// 等待完全关闭
	<-idleConnsClosed
	fmt.Println("Done!")
}

// 恶意节点监察服务
// 检查连接服务器的是否为恶意节点清单里的。
// 主进程传入连接节点地址的字符串表示，服务进程检查并返回：
// banQuery:
//   - 是：返回原值（有）
//   - 否：返回空串（无）
//   - 是，但超期，则移除后返回空串
//
// 主进程对节点判定恶意后传入添加，单向传递。
// 注：
// 除了用户外部配置的外，恶意节点仅为即时存在，并不存储。
// 因为如果程序退出，新连接的节点已经变化。
func serverBans(ctx context.Context, bans map[string]time.Time) {
	log.Println("Start peer banning server.")
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case ip := <-banQuery:
			tm, ok := bans[ip]
			if !ok {
				banQuery <- ""
				break
			}
			// 超期移除
			if time.Now().After(tm.Add(config.BanExpired)) {
				delete(bans, ip)
				banQuery <- ""
				log.Println("Remove a ban peer:", ip)
				break
			}
			banQuery <- ip
		// 添加新禁闭
		case ip := <-banAddto:
			bans[ip] = time.Now()
			log.Println("Add a ban peer in pool:", ip)
		}
	}
	log.Println("Peer banning server exit.")
}

// 应用端连接池巡查服务
// 定时巡查，检查节点接入时间是否超期，移除获取空间。
// 注记：
// 应用繁忙的节点池会在池满时强制清理，此清理与过期时间无关。
// 因此本巡查主要针对不忙的应用类型。
// @ctx 当前上下文传递
// @pool 应用节点连接池
// @dur 巡查间隔时间
func serverPatrol(ctx context.Context, pools node.ClientsPool, dur time.Duration) {
	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	// 服务名清单（全部）
	servlist := serviceList()
	log.Println("Start client pools patrol server.")
loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case <-ticker.C:
			pools.Clean(servlist, config.ClientExpired)
		}
	}
	log.Println("Client pools patrol server exit.")
}

// 初始节点搜寻处理服务
// 从 chin 接收 ips.Finding 找到的有效节点，创建连接并请求上线协助。
// 接收上线协助收到的节点信息，测试节点在线情况、汇入候选池。
// 当组网池满之后，通知 ips.Finding 搜寻结束，本服务也完成初始构造任务。
func serverPeers(ctx context.Context, chin <-chan *config.Peer, done chan struct{}, pool *node.Finders, list *node.Pool) {
	log.Println("First peers help server start.")
loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case peer := <-chin:
			if pool.IsFulled() {
				close(done)
				break loop
			}
			if err := findingsHelp(peer, 0, list, banAddto); err != nil {
				log.Printf("[Error] First help from [%s] failed on %s.", peer, err)
			}
			// 触发组网池补充操作。
			go finderReplenish(pool, list, banAddto)
		}
	}
	log.Println("First peers help server exited.")
}

// Finder巡查服务
// 定时检查组网池和候选池节点情况：
// - 如果连接池成员充足，随机更新一个连接。
// - 如果连接池成员不足，从候选池提取随机成员补充至满员。
// - 如果组网池&候选池成员数量超额，清理多出的成员，维持系统设定的上限。
// - 另外随机选1个成员，分享节点信息（COMMAND_PEER）。
// 清理策略：
// 优先移除距离较远的节点，同时兼顾随机性。
// 1. 成员随机排列，检查节点距离，超出某一阈值即移除，直到满足定额。
// 2. 如果依然超额，随机移除（忽略距离）。
// 注记：
// 节点间交换信息融入候选池时，会先检查交换的节点的在线情况。
// 从候选池取出节点补充组网池连接时，也会再测试一次对端是否在线。
// 因此候选池不再设计单独的定时在线检查服务。
// @ctx 当前上下文
// @pool 待监测的组网池
// @list 候选池（备用节点）
// @dur 巡查时间间隔
func serverFinders(ctx context.Context, pool *node.Finders, list *node.Pool, dur time.Duration) {
	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	log.Println("Start finders patrol server.")
loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case <-ticker.C:
			// 超出部分清理
			list.Trim()
			if dels := pool.Trim(); dels != nil {
				for _, fd := range dels {
					fd.Conn.Close()
				}
			}
			// 随机一成员分享
			if its := pool.Random(); its != nil {
				if err := finderShare(its, list, banAddto, config.COMMAND_PEER); err != nil {
					log.Println("[Error] Finder share peers failed:", err)
				}
			}
			// 更新|补足（隐含分享）
			if pool.IsFulled() {
				finderUpdate(pool, list, banAddto)
				break
			}
			finderReplenish(pool, list, banAddto)
		}
	}
	log.Println("Finders patrol server exited.")
}

// 连接处理器（各种需求服务）
func handleConnect(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Failed to upgrade to WebSocket:", err)
		return
	}
	defer conn.Close()

loop0:
	for {
		typ, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading message:", err)
			break
		}
		// 简单交互
		if typ == websocket.TextMessage {
			switch string(msg) {
			// 可连接探测
			case config.CmdFindPing:
				err = conn.WriteMessage(websocket.TextMessage, []byte(config.CmdFindOK))
				if err != nil {
					log.Println("Write websocket error:", err)
				}
				break loop0
			// 上线协助
			// 临时连接，即时断开。
			case config.CmdFindHelp:
				if err := findingsPush(conn, shortList, config.PeersHelp, config.COMMAND_HELP); err != nil {
					http.Error(w, "Some internal errors", http.StatusInternalServerError)
				}
				break loop0
			// 结束连接
			case config.CmdFindBye:
				if err := findings.Remove(conn); err != nil {
					log.Println("The connection was closed by", conn.RemoteAddr())
				}
				// 触发补充&检查
				finderReplenish(findings, shortList, banAddto)
				break loop0

			// 第三方NewHost请求
			// 对端请求自己向目标客户发送一个UDP探测信号。
			case config.CmdStunHost:

			// 第三方NewHost请求确认
			// 自己一方发出NewHost请求协助后，对端的确认回应。
			case config.CmdStunHosted:

			// 不合格消息
			default:
				invalidMessage(w)
			}
			continue
		}

		// 服务交互
		cmd, data, err := config.DecodeProto(msg)
		if err != nil {
			log.Println("Error decoding protobuf data:", err)
		}
		switch cmd {
		// 信息互助
		// 组网池持久连接中的信息分享。
		case config.COMMAND_PEER:
			findingsPeers(data, w, conn, shortList, config.SomeFindings, config.COMMAND_PEER)

		// 组网连接
		// 无论如何都会分享信息，如果连接池已满则不加入组网池。
		case config.COMMAND_JOIN:
			findingsPeers(data, w, conn, shortList, config.SomeFindings, config.COMMAND_JOIN)

			if findings.IsFulled() {
				log.Printf("[%s] try to connect but pool fulled.\n")
				http.Error(w, "Too many connections", http.StatusTooManyRequests)
				break loop0
			}
			its := node.NewWithAddr(conn.RemoteAddr())
			if its != nil {
				findings.Add(node.NewFinder(its, conn))
			}

		// 打洞协助（UDP）
		case config.COMMAND_STUN:
			kind, punch, err := stun.DecodePunch(data)
			if err != nil {
				log.Println("Error decode punches data.")
				http.Error(w, "Punches data is invalid", http.StatusBadRequest)
				break
			}
			if !clientPools.Supported(kind) {
				log.Println("The client type is unsupported")
				http.Error(w, "The client type is unsupported", http.StatusNotFound)
				break
			}
			pools := []*node.Clients{
				clientPools.Clients(kind, stun.NAT_LEVEL_NULL),
				clientPools.Clients(kind, stun.NAT_LEVEL_RC),
				clientPools.Clients(kind, stun.NAT_LEVEL_PRC),
			}
			servicePunching(conn, punch, pools)

		// NAT 侦测主服务
		case config.COMMAND_STUN_CONE:

		// NAT 侦测副服务
		case config.COMMAND_STUN_SYM:

		// NAT 生存期侦测
		case config.COMMAND_STUN_LIVE:

		// 消息不合规
		default:
			invalidMessage(w)
		}
	}
	// 结束通知
	conn.WriteMessage(websocket.TextMessage, []byte(config.CmdFindBye))
}

// 发送本网节点集信息
// @conn 当前连接
// @pool 节点提取来源池（候选池）
// @max 提取节点的最大数量
func findingsPush(conn *websocket.Conn, pool *node.Pool, max int, cmd config.Command) error {
	data, err := node.EncodePeers(
		pool.List(max),
	)
	if err != nil {
		log.Println("Error encoding findings peers:", err)
		return err
	}
	data, err = config.EncodeProto(cmd, data)
	if err != nil {
		log.Println("Error encoding protodata:", err)
	}
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		log.Println("Error send peers message:", err)
		return err
	}
	return nil
}

// 获取对端发送的节点集信息。
// 解码对端的数据，检查测试节点集成员的在线情况，然后汇入候选池。
// @conn 当前连接
// @pool 有效节点汇入池（候选池）
// @qban 禁闭查询通道
func findingsGets(data []byte, pool *node.Pool, qban chan string) error {
	nodes, err := node.DecodePeers(data)
	if err != nil {
		log.Println("Error decoding client peers data.", err)
		return err
	}
	// 排除被禁闭的
	nodes = filterBanned(nodes, qban)

	if len(nodes) > 0 {
		// 仅在线的节点入池。
		pool.AddNodes(node.Onlines(nodes, 0), true)
	}
	return nil
}

// 服务器：双方交换节点信息
// 这只是一个调用便利封装，conn写入应顶级执行。
// @w 原生连接符，仅用于写入错误提示
// @conn 当前连接
// @pool 有效节点获取&汇入池（候选池）
// @amount 发送的信息量
// @cmd 关联指令名
func findingsPeers(data []byte, w http.ResponseWriter, conn *websocket.Conn, pool *node.Pool, amount int, cmd config.Command) {
	go func() {
		// 在线测试耗时，故独立协程
		if err := findingsGets(data, pool, banQuery); err != nil {
			http.Error(w, "Some internal errors", http.StatusInternalServerError)
		}
	}()
	if err := findingsPush(conn, pool, amount, cmd); err != nil {
		http.Error(w, "Some internal errors", http.StatusInternalServerError)
	}
}

// 初始上线协助处理。
// 向目标节点发送上线协助请求，然后接收对端的回应。
// 回应的节点信息（在线探测后）会汇入到候选池。
// @peer 目标节点
// @long 拨号等待超时设置
// @pool 汇入的节点池（候选池）
func findingsHelp(peer *config.Peer, long time.Duration, pool *node.Pool, aban chan<- string) error {
	if pool.IsFulled() {
		return nil
	}
	conn, err := node.WebsocketDial(peer.IP, int(peer.Port), long)
	if err != nil {
		log.Println("[Error] First dial peer failed:", err)
		return err
	}
	// 请求协助
	if err = conn.WriteMessage(websocket.TextMessage, []byte(config.CmdFindHelp)); err != nil {
		log.Println("[Error] First write help command failed:", err)
		return err
	}
	// 接收协助
	if err = receivePeers(conn, pool, config.COMMAND_HELP); err != nil {
		log.Println("[Error] First receive help peer failed:", err)
		aban <- conn.RemoteAddr().String()
		return err
	}
	return nil
}

//
// 工具函数
//-----------------------------------------------------------------------------
//

// 从候选池创建一个Finder
// 会持续从候选池中提取节点，直到目标节点可用。
// @pool 节点取用源（候选池）
func createFinder(pool *node.Pool) (*node.Finder, error) {
	for {
		its := pool.Pick()
		if its == nil {
			return nil, errors.New("The shortlist was empty")
		}
		conn, err := node.WebsocketDial(its.IP, int(its.Port), 0)
		if err != nil {
			log.Println("[Error] The shortlist node was offline:", err)
			continue
		}
		return node.NewFinder(its, conn), nil
	}
}

// 组网池成员补充至满员。
// 从候选池中取出节点，直到找到一个在线的对端。
// @pool 组网池
// @list 候选池
func finderReplenish(pool *node.Finders, list *node.Pool, aban chan<- string) {
	for {
		if pool.IsFulled() {
			break
		}
		new, err := createFinder(list)
		if err != nil {
			log.Println("[Error] Create finder failed:", err)
			break
		}
		if err = finderShare(new, list, aban, config.COMMAND_JOIN); err != nil {
			log.Println("[Error] Finder first share peers failed:", err)
			continue
		}
		pool.Add(new)
	}
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
func finderUpdate(pool *node.Finders, list *node.Pool, aban chan<- string) error {
	var new *node.Finder
	var err error
	for {
		new, err = createFinder(list)
		if err != nil {
			log.Println("[Error] Create finder failed:", err)
			return err
		}
		if err = finderShare(new, list, aban, config.COMMAND_JOIN); err != nil {
			log.Println("[Error] Finder first share peers failed:", err)
			continue
		}
		break
	}
	// 先随机移除
	del := pool.Pick()
	if del != nil {
		del.Conn.WriteMessage(websocket.TextMessage, []byte(config.CmdFindBye))
		del.Conn.Close()
	}
	return pool.Add(new)
}

// 组网池成员信息分享
// - 向对端发送分享指令及其数据。
// - 接收对端回应的分享数据。
// @finder 组网节点
// @list 分享来源（候选池）
// @aban 禁闭通知通道
// @cmd 分享类指令（COMMAND_JOIN|COMMAND_PEER）
func finderShare(finder *node.Finder, list *node.Pool, aban chan<- string, cmd config.Command) error {
	var err error
	// 分享节点信息
	if err = findingsPush(finder.Conn, list, config.SomeFindings, cmd); err != nil {
		return err
	}
	// 接收分享回馈
	if err = receivePeers(finder.Conn, list, cmd); err != nil {
		log.Println("[Error] Receive shared peers failed:", err)
		// 加入黑名单
		// 理由：在线且可正常接收数据，但无法提供正常的服务。
		aban <- finder.Conn.RemoteAddr().String()
	}
	return err
}

// 应用端打洞协助
// 参考对端的NAT类型，匹配恰当的互连节点，为它们提供信令服务。
// @conn 请求源客户端连接
// @punch 源客户端打洞信息包
// @pools NAT 节点池组（0:Pub/FullC; [1]:RC; [2]:P-RC）
func servicePunching(conn *websocket.Conn, punch *stun.Puncher, pools []*node.Clients) {
	//
}

// 返回提供的服务类型名称集。
func serviceList() []string {
	list := make([]string, 0, len(stakePool))

	for name := range stakePool {
		list = append(list, name)
	}
	return list
}

// 查询服务类型的受益账号。
func serviceStake(name string) string {
	return stakePool[name]
}

// 接收对端分享的节点信息。
// 此为客户端向服务器发送请求信息指令后，接收对端的数据。
// @conn 目标连接
// @pool 待汇入目标（候选池）
// @cmdx 欲匹配的消息指令
func receivePeers(conn *websocket.Conn, pool *node.Pool, cmdx config.Command) error {
	typ, msg, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if typ != websocket.BinaryMessage {
		return errors.New("Receive shared peers datatype invalid")
	}
	cmd, data, err := config.DecodeProto(msg)

	if err != nil {
		return err
	}
	if cmd != cmdx {
		return errors.New("Decoded protodata command is invalid")
	}
	return findingsGets(data, pool, banQuery)
}

// 禁闭节点过滤
// @nodes 原节点集
// @ban 禁闭查询通道
// @return 未禁闭的节点集
func filterBanned(nodes []*node.Node, ban chan string) []*node.Node {
	buf := make([]*node.Node, 0, len(nodes))

	for _, node := range nodes {
		if ip := <-ban; ip != "" {
			log.Println("[Warning] The banned ip: ", ip)
			continue
		}
		buf = append(buf, node)
	}
	return buf
}

// 无效消息通知&日志记录
func invalidMessage(w http.ResponseWriter) {
	log.Println("The message sent by the client is illegal.")
	http.Error(w, "The message is illegal", http.StatusMisdirectedRequest)
}
