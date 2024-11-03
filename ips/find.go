package ips

import (
	"context"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/cxio/findings/config"
	"github.com/cxio/findings/node"
)

const (
	randomAmount  = 50                     // 批量随机节点集大小
	bringInterval = time.Millisecond * 400 // 并发测试创建间隔（避免系统负荷急增）
)

// Finding 对外寻找节点尝试连接
// 会优先尝试外部提供的节点清单，如果无果则进入随机尝试（漫长）。
// 找到节点后向组网池中添加，直到池满搜寻结束。
// 注：
// 当主进程连接到先找到的节点交换了信息后，组网池可能会提前充满。
// @port 远端节点端口
// @peers 优先尝试的节点清单（作为目标和起点）
// @size 基于起点ip的搜寻幅度（范围）
// @return1 有效节点递送通道
// @return2 结束搜寻通知机制（通道）
func Finding(ctx context.Context, port int, peers map[netip.Addr]*config.Peer, size int) (<-chan *config.Peer, chan<- struct{}) {
	log.Println("Start searching findings peers...")

	// 节点输出
	out := make(chan *config.Peer, 1)
	defer close(out)

	// 结束通知（外部）
	done := make(chan struct{})

	go func() {
		// 1. 首先：
		// 对用户配置的节点尝试连接
		peersTesting(ctx, peers, -1, out, done)

		// 排除清单
		exclude := excludeAppend(nil, peers)

		// 2. 范围：
		// 对配置节点的周边尝试探测
		for _, peer := range peers {
			select {
			case <-ctx.Done():
				log.Println("Break search on context EXIT.")
				return
			case <-done:
				log.Println("Peers searching completed successfully.")
				return
			default:
				list := peerList(
					rangeAddrs(peer.IP, size),
					port,
					exclude)

				// 阻塞：探测完一批后再来
				peersTesting(ctx, list, -1, out, done)

				// 已探测添加
				exclude = excludeAppend(exclude, list)
			}
		}

		// 3. 随机：
		// 无限时间！直到成功或外部主动结束
		for {
			select {
			case <-ctx.Done():
				log.Println("Break search on context EXIT.")
				return
			case <-done:
				log.Println("Peers searching completed successfully.")
				return
			default:
				ips := randomAddrs(randomAmount)

				// 概略化处理
				// 随机范围宽广，exclude 不再更新。
				peersTesting(ctx, peerList(ips, port, exclude), -1, out, done)
			}
		}
	}()

	log.Println("End peers search service.")
	return out, done
}

// 节点集测试
// 批量并行测试，但阻塞直到全部结束才返回。
// @ctx 全局上下文通知
// @peers 目标节点集
// @long 连接尝试超时时长
// @chout 合格节点对外递送通道
// @done 外部结束通知
func peersTesting(ctx context.Context, peers map[netip.Addr]*config.Peer, long time.Duration, chout chan<- *config.Peer, done <-chan struct{}) {
	var wg sync.WaitGroup

loop:
	for _, peer := range peers {
		wg.Add(1)

		go func(p *config.Peer) {
			defer wg.Done()
			nd := node.New(p.IP, int(p.Port))

			if err := nd.Online(long); err != nil {
				log.Printf("[%s] is unreachable on %s.\n", p, err)
				return
			}
			chout <- p
			log.Printf("[%s] is validly.", p)
		}(peer)

		select {
		case <-ctx.Done():
			break loop
		case <-done:
			log.Println("Peers searching completed successfully.")
			break loop
		// 适当停顿
		case <-time.After(bringInterval):
		}
	}

	wg.Wait() // 阻塞直到全部结束
}

// 构造节点对象集。
// 用多个IP地址，但端口为共同的一个。
// @ips 地址IP清单
// @port 共同端口
// @exclude IP例外清单
// @return 节点集
func peerList(ips []netip.Addr, port int, exclude map[netip.Addr]bool) map[netip.Addr]*config.Peer {
	list := make(map[netip.Addr]*config.Peer)

	for _, ip := range ips {
		if _, ok := exclude[ip]; ok {
			continue
		}
		list[ip] = &config.Peer{IP: ip, Port: uint16(port)}
	}
	return list
}

// 排除清单成员补充
// 如果清单存储目标为nil，会新建一个存储区返回。
// @dst 清单存储
// @src 来源清单
// @return 存储的清单
func excludeAppend(dst map[netip.Addr]bool, src map[netip.Addr]*config.Peer) map[netip.Addr]bool {
	if dst == nil {
		dst = make(map[netip.Addr]bool)
	}
	for _, peer := range src {
		dst[peer.IP] = true
	}
	return dst
}
