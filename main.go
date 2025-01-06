// Copyright (c) 2024 @cxio/findings
// Released under the MIT license
//////////////////////////////////////////////////////////////////////////////
//
// 节点发现服务
// ------------
// 节点相互连接构建为一个P2P网络，向应用类节点提供其同类节点的信息，
// 同时也支持NAT层级探查和STUN打洞服务（含定向打洞）。
//
// 另外也支持应用的TCP公网服务节点登记和分享。
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
// 公网节点的当前连接池，Websocket（TCP）连接。
// 池成员可能为其它公网类节点，也可能是受限节点（此时为连入）。
// 当前节点除了维持Findings网络的运行外，也协助应用池的STUN探测服务。
//
// 应用池：
// -------
// 接受其它各类应用节点的连入，提供NAT探测和打洞服务。
// 能提供打洞服务的Findings节点是公网节点，因为只有它们能直接接收连入。
//
// 分享池：
// --------
// 接受各种应用的TCP可直连服务器登记，以及相应应用对其服务器信息的获取。
//
//////////////////////////////////////////////////////////////////////////////
//

// Findings 主程序。
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/cxio/findings/base"
	"github.com/cxio/findings/config"
	"github.com/cxio/findings/crypto/selfsign"
	"github.com/cxio/findings/ips"
	"github.com/cxio/findings/node"
	"github.com/gorilla/websocket"
)

// websocket 升级器
var upgrader = websocket.Upgrader{
	ReadBufferSize:  config.BufferSize,
	WriteBufferSize: config.BufferSize,
}

// 服务器关闭等待
var idleConnsClosed = make(chan struct{})

// 程序退出延时
// 注：部分协程里需要关闭文件。
const idleAllExit = time.Second * 5

// 便捷引用
var loger = base.Log
var logpeer = base.LogPeer

func main() {
	// 读取基础配置
	cfg, err := config.Base()
	if err != nil {
		loger.Fatalln("[Fatal] reading base config:", err)
	}
	if cfg.BufferSize > 0 {
		upgrader.ReadBufferSize = cfg.BufferSize
		upgrader.WriteBufferSize = cfg.BufferSize
	}

	// 读取可用节点配置
	peers, err := config.Peers()
	if err != nil {
		loger.Fatalln("[Fatal] reading peers config:", err)
	}
	// 恶意节点清单
	bans, err := config.Bans()
	if err != nil {
		loger.Fatalln("[Fatal] reading ban list:", err)
	}

	// 服务器权益账户
	stakes, err := config.Stakes()
	if err != nil {
		loger.Fatalln("[Fatal] reading stakes of server:", err)
	}
	// 上下文环境
	ctx, cancel := context.WithCancel(context.Background())

	// 日志初始化：
	// base.[Log, LogPeer, LogDebug]
	base.LogsInit(ctx, cfg.LogDir)

	// 向外寻找 Finder
	chpeer, done := ips.Finding(ctx, cfg.RemotePort, peers, cfg.PeerFindRange)

	// 节点模块初始化
	node.Init(ctx, cfg, stakes, chpeer, done)

	// 恶意节点监察
	go serverBans(ctx, bans, node.BanAddto, node.BanQuery)

	// 阻塞：启动服务
	serviceListen(cfg.ServerPort)
	cancel()

	log.Println("Waiting a moment for server to exit...")
	<-time.After(idleAllExit)

	loger.Println("Findings service EXIT.")
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
		loger.Fatalln("[Fatal] generate self-signed certificate failed:", err)
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
	loger.Println("Server is running on port", port)

	// 用户中断监听，友好关闭
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		// 关闭提示...
		go func() {
			loger.Print("Shutting down the server")
			for {
				fmt.Print(".")
				<-time.After(time.Second)
			}
		}()
		if err := server.Shutdown(context.TODO()); err != nil {
			loger.Println("[Error] server shutdown:", err)
		}
		close(idleConnsClosed)
	}()
	// 阻塞：服务器运行
	if err = server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		loger.Fatalln("[Fatal] starting server:", err)
	}

	// 等待完全关闭
	<-idleConnsClosed
	fmt.Println("Done!")
}

// 恶意节点监察服务
// 检查连接服务器的是否为恶意节点清单里的。
// 主服务进程传入连接节点地址的字符串表示，监察进程检查并返回：
// banQuery:
//   - 是：返回原值（有）
//   - 否：返回空串（无）
//   - 是，但超期，则移除后返回空串
//
// 主服务进程对节点判定恶意后传入添加，单向传递。
// 注：
// 除了用户外部配置的外，恶意节点仅为即时存在，并不存储。
// 因为如果程序退出，新连接的节点已经变化。
func serverBans(ctx context.Context, bans map[string]time.Time, banAddto chan string, banQuery chan *node.Banner) {
	loger.Println("Start peer banning server.")
loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case ban := <-banQuery:
			tm, ok := bans[ban.Addr]
			if !ok {
				ban.Close() // as false
				break
			}
			// 超期移除
			if time.Now().After(tm.Add(config.BanExpired)) {
				delete(bans, ban.Addr)
				ban.Close()
				logpeer.Println("remove a banned peer:", ban.Addr)
				break
			}
			// 禁闭中
			ban.Reply <- true
			ban.Close()

		// 添加新禁闭
		case addr := <-banAddto:
			bans[addr] = time.Now()
			logpeer.Println("add a banned peer:", addr)
		}
	}
	loger.Println("Peer banning server exit.")
}

// 连接处理器
// 处理任意对端节点进入的连接，对端初始发送的消息只能是如下两者：
//
// 1. 网络探测：
// 探查本节点是否为Findings网络节点。回复后即结束，不接受进一步的操作。
// 发送消息为文本，值为 base.CmdFindPing 变量的值。
//
// 2. 节点声明：
// 提供自己的基本信息。
// - 应用自身所属的类别（findings|depots|blockchain|app）和名称。
// - 应用所寻求的服务（find:net|assist:x|kind:app|app:serv|peer:tcp）。
//
// 节点声明之后，即可开始后续的逻辑。
func handleConnect(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		loger.Println("[Error] upgrade websocket:", err)
		return
	}
	defer conn.Close()

	// 初始信息读取
	typ, msg, err := conn.ReadMessage()
	if err != nil {
		loger.Println("[Error] reading message:", err)
		return
	}
	switch typ {
	// 网络探测：
	// 视为临时连接，即时关闭。
	case websocket.TextMessage:
		if string(msg) != base.CmdFindPing {
			loger.Println("[Error] first message not ping.")
			http.Error(w, "First message invalid", http.StatusBadRequest)
			break
		}
		if err = conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindOK)); err != nil {
			loger.Println("[Error] write websocket:", err)
			http.Error(w, "First message invalid", http.StatusInternalServerError)
		}
	// 节点声明：
	case websocket.BinaryMessage:
		cmd, data, err := base.DecodeProto(msg)
		if err != nil {
			loger.Println("[Error] decoding protobuf data:", err)
			http.Error(w, "Decoding data failed", http.StatusInternalServerError)
			break
		}
		if cmd != base.COMMAND_KIND {
			loger.Println("[Error] first command is bad.")
			http.Error(w, "First command is bad", http.StatusInternalServerError)
			break
		}
		kind, err := base.DecodeKind(data)
		if err != nil {
			loger.Println("[Error] decode kind on", err)
			http.Error(w, "Decode kind failed", http.StatusBadRequest)
			break
		}
		// 按类别处理（顶层）
		node.ProcessOnKind(kind, conn, w)
	}
	// 友好
	conn.WriteMessage(websocket.TextMessage, []byte(base.CmdFindBye))
}
