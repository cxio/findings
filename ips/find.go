package ips

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/cxio/findings/config"
)

// Finding 对外寻找节点尝试连接
// 会优先尝试外部提供的节点清单，如果无果则进入随机尝试（漫长）。
// 找到节点后向组网池中添加，直到池满搜寻结束。
// 注：
// 当主进程连接到先找到的节点交换了信息后，组网池可能会提前充满。
// @port 远端节点端口
// @peers 优先尝试的节点清单（作为目标和起点）
// @size 基于起点ip的搜寻幅度（范围）
// @chout 有效节点递送通道
// @chdone 结束搜寻通知通道
func Finding(ctx context.Context, port int, peers []config.Peer, size int, chout chan<- *config.Peer, done chan struct{}) {
	log.Println("Start searching findings peers...")

	// 1. 首先对配置的节点尝试连接
	for _, peer := range peers {
		connectPeer(ctx, peer)
	}
	// 2. 对配置节点的周边尝试连接

	// 3. 随机尝试，最下策，长时间……
	for {
		select {
		case <-ctx.Done():
			log.Printf("End search the servers")
			break
		default:
		}
	}
}

// 获取随机目标尝试连接
func randomConnects(ctx context.Context, port int) error {
	//
}

// 从一个范围尝试连接
// ip 是目标范围的一个参考点，但不含目标。
// 范围大小由size指定，目标IP集在ip的前后size范围内。
func rangeConnects(ctx context.Context, port int, ip netip.Addr, size int) error {
	//
}

// 对明确目标尝试连接
func connectPeer(ctx context.Context, peer config.Peer) bool {
	//
}

//
// 代码参考（临时）
///////////////////////////////////////////////////////////////////////////////
//

// 启动对外连接
// 端口可能为零，表示采用动态端口侦测模式（暂未实现）。
// @port 连接目标节点的端口号
// @num Findings节点最大连接数量
func connectFindings(port int, num int) {
	fmt.Println("Connecting findings peer...")

	done := make(chan struct{}) // 用于接收连接关闭通知
	wg := &sync.WaitGroup{}

	// 创建初始连接
	for i := 0; i < num; i++ {
		wg.Add(1)
		go createConnection(i, port, done, wg)
	}

	// 监听连接关闭通知，动态维持连接数
	go func() {
		for range done {
			// 收到连接关闭通知后，创建新的连接
			wg.Add(1)
			go createConnection(num, port, done, wg)
			num++
		}
	}()
	close(done) // 关闭done channel，停止创建新连接
	wg.Wait()   // 等待所有连接结束
}

// 向外连接客户端
// 如果返回一个错误，通常表示目标节点不支持本协议的连接。
// 注记：
// 这是一种随机目标连接，连接错误是可预期的，因此不记入日志。
func connectClient(ip string, port int) error {
	addr := fmt.Sprintf("%s:%d", ip, port)

	fmt.Println("Connect client...", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("Error connect client:", err)
		return err
	}
	defer conn.Close()

	// ... 客户端逻辑实现

	return nil
}

// 创建连接
// 失败退出后，上级会自动创建新的连接尝试，以维持节点连接数。
// 注记：
// 注意检查上级是否主动关闭done，以跟随清理并退出。
func createConnection(id, port int, done chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		done <- struct{}{} // 发送连接关闭通知
	}()

	fmt.Printf("Connection %d started\n", id)

	fmt.Printf("Connection %d closed\n", id)
}
