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
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/cxio/findings/base"
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
	shortList *node.Shortlist

	// 组网池
	findings *node.Finders

	// 应用端节点池集
	applPools node.AppliersTeams

	// 禁闭查询通道
	// 无缓存，维持不同请求间并发安全。
	banQuery = make(chan string)

	// 禁闭添加通道
	// 单向添加用途，故带缓存无阻塞。
	banAddto = make(chan string, 1)

	// 服务器关闭等待
	idleConnsClosed = make(chan struct{})

	// NAT 探测协作通知渠道
	stunNotice = make(chan *stun.Notice, 1)

	// NAT 探测客户端信息通道
	stunClient <-chan *stun.Client
)

var (
	// 应用端节点池组为空
	errAppliersEmpty = errors.New("the clients pools is empty")

	// 没有匹配的打洞节点
	errApplierNotFound = errors.New("no matching nodes on STUN service")
)

func main() {
	// 读取基础配置
	cfg, err := config.Base()
	if err != nil {
		log.Fatalln("[Error] reading base config:", err)
	}
	if cfg.BufferSize > 0 {
		upgrader.ReadBufferSize = cfg.BufferSize
		upgrader.WriteBufferSize = cfg.BufferSize
	}

	// 读取可用节点配置
	peers, err := config.Peers()
	if err != nil {
		log.Fatalln("[Error] reading peers config:", err)
	}
	// 恶意节点清单
	bans, err := config.Bans()
	if err != nil {
		log.Fatalln("[Error] reading ban list:", err)
	}

	// 服务器权益账户
	// 注意：赋值到全局变量上。
	stakePool, err = config.Services()
	if err != nil {
		log.Fatalln("[Error] reading stakes of server:", err)
	}

	// 全局节点池
	shortList = node.NewShortlist(cfg.Shortlist)
	findings = node.NewFinders(cfg.Findings)
	applPools = node.NewAppliersPool()

	// 应用集支持
	for _, kn := range serviceList() {
		// 大小和长度参数暂为统一
		// 此为逐个设置，必要时可为每种应用配置不同的限额。
		applPools.Init(base.KindName(kn), cfg.ConnApps, config.AppCleanLen)
	}

	// 上下文环境
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动两个UDP服务器
	go func() {
		stunClient = stun.ListenUDP(ctx, config.UDPListen, base.GlobalSeed, stunNotice)
	}()
	go stun.LiveListen(ctx, config.UDPLiving, base.GlobalSeed)

	// 恶意节点监察
	go serverBans(ctx, bans)

	// 应用清理巡查
	// 主要用于不忙的应用清理太旧的信息以节省系统内容。
	go serverPatrol(ctx, applPools, config.ApplierPatrol)

	// 初始节点探测递送通道
	// 通道两端皆为耗时操作，给与缓存自适应。
	chpeer := make(chan *config.Peer, 1)

	// 初始节点探测结束通知
	chdone := make(chan struct{})

	// 向外寻找 Finder
	go ips.Finding(ctx, uint16(cfg.RemotePort), peers, cfg.PeerFindRange, chpeer, chdone)

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
		log.Fatalln("[Error] generate self-signed certificate failed:", err)
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
			log.Println("[Error] server shutdown:", err)
		}
		close(idleConnsClosed)
	}()
	// 启动服务器
	if err = server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatalln("[Error] starting server:", err)
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
func serverPatrol(ctx context.Context, pools node.AppliersPool, dur time.Duration) {
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
			pools.Clean(servlist, config.ApplierExpired)
		}
	}
	log.Println("applier pools patrol server exit.")
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
			// 分享出错会简单忽略，打印出错消息后续继续。
			if its := pool.Random(); its != nil {
				if err := finderShare(its, list, banAddto, base.COMMAND_PEER); err != nil {
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

// ListenUDP 本地UDP服务器
func ListenUDP(ctx context.Context, port int) {
	//
}

// 连接处理器（主）
// 处理任意对端节点进入的连接，对端初始发送的消息只能是如下两者：
//
// 1. 网络探测：
// 探查本节点是否为Findings网络节点。回复后即结束，不接受进一步的操作。
// 发送消息为文本，值为 base.CmdFindPing 变量的值。
//
// 2. 类型声明：
// 指定自身需要的服务类型：findings | ...
// 当指定类型为 findings 时，节点自身可能是 Finder，也可能是应用端需要获得 Findings 网络服务节点。
// ... 为任意应用名称。
// 类型声明为二进制格式，携带标识关键字和类型名。
//
// 类型声明之后，即可开始后续的逻辑。
func handleConnect(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("[Error] upgrade websocket:", err)
		return
	}
	defer conn.Close()

	// 初始信息读取
	typ, msg, err := conn.ReadMessage()
	if err != nil {
		log.Println("[Error] reading message:", err)
		return
	}
	switch typ {
	// 网络探测：
	// 视为临时连接，即时关闭。
	case websocket.TextMessage:
		if string(msg) != base.CmdFindPing {
			log.Println("[Error] first message not ping.")
			http.Error(w, "First message invalid", http.StatusBadRequest)
			break
		}
		if err = conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindOK)); err != nil {
			log.Println("[Error] write websocket:", err)
			http.Error(w, "First message invalid", http.StatusInternalServerError)
		}
	// 类型声明
	case websocket.BinaryMessage:
		cmd, kind, err := base.DecodeProto(msg)
		if err != nil {
			log.Println("[Error] decoding protobuf data:", err)
			http.Error(w, "Decoding data failed", http.StatusInternalServerError)
			break
		}
		if cmd != base.COMMAND_KIND {
			log.Println("[Error] first command is bad.")
			http.Error(w, "First command is bad", http.StatusInternalServerError)
			break
		}
		kname, err := base.DecodeKind(kind)
		if err != nil {
			log.Println("[Error] decode kind on", err)
			http.Error(w, "Decode kind failed", http.StatusBadRequest)
			break
		}
		// 按类别处理（顶层）
		processOnKind(kname, conn, w)
	}
	// 结束通知
	conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindBye))
}

// 按目标类型的初始处理。
// @kname 应用端名
// @conn 当前TCP连接
// @w 原始http写入器
func processOnKind(kname *base.Kind, conn *websocket.Conn, w http.ResponseWriter) {
	switch kname.Base {
	// findings:
	case base.BASEKIND_FINDINGS:
		//

	// others:
	default:
		//
	}
}

// 通用处理器
// handleConnect 的子处理器，仅用于代码分解。
// @conn 当前连接
// @w 原始http连接
// @return 返回true表示正常处理，上层继续，否则上层结束
func normalProcess(conn *websocket.Conn, w http.ResponseWriter) bool {
	typ, msg, err := conn.ReadMessage()
	if err != nil {
		log.Println("[Error] reading message:", err)
		return false
	}
	// 简单交互
	if typ == websocket.TextMessage {
		return simpleProcess(string(msg), conn, w)
	}

	// 服务交互
	cmd, data, err := base.DecodeProto(msg)
	if err != nil {
		log.Println("[Error] decoding protobuf data:", err)
		return false
	}
	switch cmd {
	// 信息互助
	// 组网池持久连接中的信息分享。
	case base.COMMAND_PEER:
		findingsPeers(data, w, conn, shortList, config.SomeFindings, base.COMMAND_PEER)

	// 组网连接
	// 无论如何都会分享信息，如果连接池已满则不加入组网池。
	case base.COMMAND_JOIN:
		findingsPeers(data, w, conn, shortList, config.SomeFindings, base.COMMAND_JOIN)

		if findings.IsFulled() {
			log.Printf("[%s] try to connect but pool fulled.\n", conn.RemoteAddr())
			http.Error(w, "Too many connections", http.StatusTooManyRequests)
			return false
		}
		its := node.NewWithAddr(conn.RemoteAddr())
		if its != nil {
			findings.Add(node.NewFinder(its, conn))
		}

	// 查询应用类型支持
	case base.COMMAND_KIND:
		msg := base.CmdKindFail

		if supportKind(string(data)) {
			msg = base.CmdKindOK
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			log.Println("[Error] write websocket:", err)
			return false
		}

	// 打洞协助（UDP）
	case base.COMMAND_STUN:
		kind, punch, err := stun.DecodePunch(data)
		if err != nil {
			log.Println("Error decode punches data.")
			http.Error(w, "Punches data is invalid", http.StatusBadRequest)
			return false
		}
		if !applPools.Supported(kind) {
			log.Println("The client type is unsupported")
			http.Error(w, "The client type is unsupported", http.StatusNotFound)
			// 不支持，退出当前连接
			return false
		}
		if err = servicePunching(conn, punch, applPools.AppliersUDP(kind), config.STUNPeerAmount); err != nil {
			log.Println("stun server failed of", err)
			http.Error(w, "stun assistance failed", http.StatusInternalServerError)
		}

	// NAT 侦测主服务
	case base.COMMAND_STUN_CONE:

	// NAT 侦测副服务
	case base.COMMAND_STUN_SYM:

	// NAT 生存期侦测
	case base.COMMAND_STUN_LIVE:

	// 应邀 NewHost
	// data 为对端传递过来的 Hosto 已编码数据。
	case base.COMMAND_STUN_HOST:
		addr, sn, err := stun.DecodeHosto(data)
		if err != nil {
			log.Println("[Error] decode hosto on", err)
			break
		}
		reply := make(chan bool)
		stunNotice <- stun.NewNotice(stun.UDPSEND_NEWHOST, addr, sn, reply)

		// 默认成功配合
		msg := base.CmdStunHostOK

		if ok := <-reply; !ok {
			msg = base.CmdStunHostFail
		}
		if err = conn.WriteMessage(websocket.BinaryMessage, []byte(msg)); err != nil {
			log.Println("[Error] write websocket message", err)
		}
		//! 不影响上层继续

	// 消息不合规
	default:
		invalidMessage(w)
	}
	return true // 上级正常迭代
}

// 简单指令处理器
// 仅负责 websocket.TextMessage 类消息的处理，无附带数据。
// @msg 对端指令字符串
// @conn 当前连接
// @w 原始http连接
// @return 返回true表示正常处理，上层继续，否则上层结束
func simpleProcess(msg string, conn *websocket.Conn, w http.ResponseWriter) bool {
	switch string(msg) {

	// 可连接探测
	case base.CmdFindPing:
		err := conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindOK))
		if err != nil {
			log.Println("[Error] write websocket:", err)
		}
		return false

	// 上线协助
	// 临时连接，即时断开。
	case base.CmdFindHelp:
		if err := findingsPush(conn, shortList, config.PeersHelp, base.COMMAND_HELP); err != nil {
			http.Error(w, "Some internal errors", http.StatusInternalServerError)
		}
		return false

	// 服务类型集
	// 通常为持续连接，后续会请求具体的帮助。
	// 注：此为应用端请求。
	case base.CmdFindKinds:
		if err := findingsKinds(conn, serviceList(), base.COMMAND_SERVKINDS); err != nil {
			log.Println("[Error] put service kinds:", err)
		}

	// 结束连接
	case base.CmdFindBye:
		if err := findings.Remove(conn); err != nil {
			log.Println("The connection was closed by", conn.RemoteAddr())
		}
		// 触发补充&检查
		finderReplenish(findings, shortList, banAddto)
		return false

	// 不合格消息
	default:
		invalidMessage(w)
	}

	return true // 上层继续
}

// 发送本网节点集信息
// @conn 当前连接
// @pool 节点提取来源池（候选池）
// @max 提取节点的最大数量
func findingsPush(conn *websocket.Conn, pool *node.Pool, max int, cmd base.Command) error {
	data, err := node.EncodePeers(
		pool.List(max),
	)
	if err != nil {
		log.Println("[Error] encoding findings peers.")
		return err
	}
	data, err = base.EncodeProto(cmd, data)
	if err != nil {
		log.Println("[Error] encoding protodata.")
		return err
	}
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		log.Println("[Error] send peers message.")
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
		log.Println("[Error] decoding client peers data.")
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
// @data 对端分享的节点清单数据
// @w 原生连接符，仅用于写入错误提示
// @conn 当前连接
// @pool 有效节点获取&汇入池（候选池）
// @amount 发送的信息量
// @cmd 关联指令名
func findingsPeers(data []byte, w http.ResponseWriter, conn *websocket.Conn, pool *node.Pool, amount int, cmd base.Command) {
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
	conn, err := node.WebsocketDial(peer.IP, peer.Port, long)
	if err != nil {
		log.Println("[Error] first dial peer.")
		return err
	}
	// 请求协助
	if err = conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindHelp)); err != nil {
		log.Println("[Error] first write help command.")
		return err
	}
	// 接收协助
	if err = receivePeers(conn, pool, base.COMMAND_HELP); err != nil {
		log.Println("[Error] first receive help peer.")
		aban <- conn.RemoteAddr().String()
		return err
	}
	return nil
}

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
			return nil, errors.New("the shortlist was empty")
		}
		conn, err := node.WebsocketDial(its.IP, its.Port, 0)
		if err != nil {
			log.Println("[Error] shortlist node was offline:", err)
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
			log.Println("[Error] create finder:", err)
			break
		}
		if err = finderShare(new, list, aban, base.COMMAND_JOIN); err != nil {
			log.Println("[Error] finder first share peers:", err)
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
			log.Println("[Error] create finder.")
			return err
		}
		if err = finderShare(new, list, aban, base.COMMAND_JOIN); err != nil {
			log.Println("[Error] finder first share peers.")
			continue
		}
		break
	}
	// 先随机移除
	del := pool.Pick()
	if del != nil {
		del.Conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindBye))
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
func finderShare(finder *node.Finder, list *node.Pool, aban chan<- string, cmd base.Command) error {
	var err error
	// 分享节点信息
	if err = findingsPush(finder.Conn, list, config.SomeFindings, cmd); err != nil {
		return err
	}
	// 接收分享回馈
	if err = receivePeers(finder.Conn, list, cmd); err != nil {
		log.Println("[Error] receive shared peers.")
		// 加入黑名单
		// 理由：在线且可正常接收数据，但无法提供正常的服务。
		aban <- finder.Conn.RemoteAddr().String()
	}
	return err
}

// 应用端打洞协助（多目标）
// @conn 请求源客户端连接
// @punch 源客户端打洞信息包
// @pools NAT 节点池组（0:Pub/FullC; 1:RC; 2:P-RC; 3:Sym）
// @amount 尝试协助互通的节点数上限
func servicePunching(conn *websocket.Conn, punch *stun.Puncher, pools []*node.Appliers, amount int) error {
	if pools == nil {
		return errAppliersEmpty
	}
	// 可能重复，因此标记
	pass := make(map[*websocket.Conn]bool)

	for n := 0; n < amount; n++ {
		client, err := punchingPeer(conn, punch, pools, config.STUNTryMax)

		// 条件不具备，无需再尝试
		if err != nil {
			return err
		}
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
func punchingPeer(conn *websocket.Conn, punch *stun.Puncher, pools []*node.Appliers, max int) (*node.Applier, error) {
	var err error
	var dir *stun.PunchDir
	var peer *node.Applier

	for n := 0; n < max; n++ {
		peer = punchMatched(punch.Level, pools)

		if peer == nil {
			return nil, errApplierNotFound
		}
		punch2 := peer.Puncher()

		// dir[0] punch
		// dir[1] punch2
		if dir, err = stun.PunchingDir(punch, punch2); err != nil {
			return nil, err
		}
		// => punch2
		// 成功即退出，否则尝试新的匹配
		if err = punchingPush(peer.Conn, dir[1], punch2, base.COMMAND_PUNCH); err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	// => punch
	return peer, punchingPush(conn, dir[0], punch, base.COMMAND_PUNCH)
}

// 向应用端连接写入打洞信息包
// 信息包依然为两级封装，内层编码需用 stun.DecodePunch 解码。
// @conn 应用端连接
// @punch 打洞信息包
// @cmd 顶层封装类别（应为 COMMAND_PUNCH）
// @return 返回错误通常表示传输失败（对端不在线）
func punchingPush(conn *websocket.Conn, dir string, punch *stun.Puncher, cmd base.Command) error {
	// 内层编码
	data, err := stun.EncodePunch(dir, punch)
	if err != nil {
		log.Println("[Error] punch data encode.")
		return err
	}
	// 顶层编码
	data, err = base.EncodeProto(cmd, data)
	if err != nil {
		log.Println("[Error] punch protobuf encode.")
		return err
	}
	// 传送到对端
	if err = conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		log.Println("[Error] send punch's data.")
	}
	return err
}

// 返回提供的服务类型名称集。
// 不符合格式（kind:name）的名称会被简单忽略。
func serviceList() []*base.Kind {
	list := make([]*base.Kind, 0, len(stakePool))

	for name := range stakePool {
		// kind:name
		kn, err := base.ParseKind(name)

		if err != nil {
			log.Println("[Error] parse kind on", err)
			continue
		}
		list = append(list, kn)
	}
	return list
}

// 查询服务类型的受益账号。
// @name 应用服务的类型名
// @return 服务器相应的收益地址（区块链账号）
func serviceStake(name string) string {
	return stakePool[name]
}

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
func punchMatched(level stun.NatLevel, pools []*node.Appliers) *node.Applier {
	// Pub/FullC
	c0 := pools[0].Get()

	if level == stun.NAT_LEVEL_SYM {
		return c0
	}
	c1 := pools[1].Get() // RC
	c2 := pools[2].Get() // P-RC
	c3 := pools[3].Get() // Sym

	switch level {
	case stun.NAT_LEVEL_PRC:
		return increaseRandomNode(c0, c2, c1)
	case stun.NAT_LEVEL_RC:
		return increaseRandomNode(c0, c1, c2)
	case stun.NAT_LEVEL_NULL:
		return increaseRandomNode(c0, c1, c2, c3)
	}
	return nil
}

// 递增法随机节点获取
// 权重值按参数顺序递增，从1开始。
// 池中添加实参成员，随着权重增加，重复添加（增加高权重项的数量）。
// 最终取一个随机位置值。
func increaseRandomNode(cs ...*node.Applier) *node.Applier {
	size := increaseSum(1, 1, len(cs))
	pool := make([]*node.Applier, 0, size)

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

// 是否支持目标类型的服务。
func supportKind(name string) bool {
	if _, ok := stakePool[name]; ok {
		return true
	}
	return false
}

// 接收对端分享的节点信息。
// 此为客户端向服务器发送请求信息指令后，接收对端的数据。
// @conn 目标连接
// @pool 待汇入目标（候选池）
// @cmdx 欲匹配的消息指令
func receivePeers(conn *websocket.Conn, pool *node.Pool, cmdx base.Command) error {
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

// 递增等差数列求和
// @a 起始值
// @d 等差值
// @n 项数
// @return 求和值
func increaseSum(a, d, n int) int {
	return n * (2*a + (n-1)*d) / 2
}
