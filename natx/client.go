// STUN 客户端。
// 实现 NAT 层级探测（STUN:Cone/Sym）和生存期探测（STUN:Live）的逻辑。
package natx

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/cxio/findings/stun"
)

// NatLevel NAT 层级类型引用
type NatLevel = stun.NatLevel

// ClientSN 客户端序列号引用
type ClientSN = stun.ClientSN

// 16字节随机序列引用
type Rnd16 = stun.Rnd16

// STUNTester NAT测试类型
type STUNTester int

const (
	STUN_CONE STUNTester = 1 + iota // STUN:Cone
	STUN_SYM                        // STUN:Sym
	STUN_LIVE                       // STUN:Live
)

var (
	// UDP拨号错误
	ErrDialUDP = errors.New("dial to server udp failed")

	// 客户端UDP地址未探测
	ErrNotAddr = errors.New("client udp addr is empty")
)

// Client 作为客户端的Finder
type Client struct {
	Level  chan NatLevel      // NAT 层级通知
	Live   chan time.Duration // NAT 生存期通知
	UDPeer chan *net.UDPAddr  // 客户端UDP地址通知
	Tester chan STUNTester    // STUN 测试类型
	conn   *net.UDPConn       // UDP 主监听连接（NAT探测）
	paddr  *net.UDPAddr       // 对端回传的公网地址
	dialok chan struct{}      // UDP 拨号结束通知
}

// NewClient 新建一个Finder客户端。
// @conn 为客户端UDP监听连接
func NewClient(conn *net.UDPConn) *Client {
	return &Client{
		conn:   conn,
		Level:  make(chan NatLevel),
		Live:   make(chan time.Duration),
		UDPeer: make(chan *net.UDPAddr),
		paddr:  nil,
		dialok: nil, // 由 Dial 赋值
	}
}

// ListenUDP 创建一个客户端UDP监听。
// 监听本地所有IP地址，采用系统自动分配的端口。
// 应用于本地受限节点。
func ListenUDP(ctx context.Context) (*Client, error) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 0,
	}
	conn, err := net.ListenUDP("udp", addr)

	if err != nil {
		return nil, err
	}
	return NewClient(conn).Serve(ctx), nil
}

// Serve 启动本地监听&判断服务。
func (c *Client) Serve(ctx context.Context) *Client {
	log.Println("Client UDP listen start")

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case addr := <-c.UDPeer:
				c.paddr = addr
				// 结束持续拨号
				close(c.dialok)

			case op := <-c.Tester:
				switch op {
				case STUN_CONE:
				case STUN_SYM:
				case STUN_LIVE:
				}
			}
		}
	}()

	return c
}

// Dial 向对端UDP服务器拨号。
// 在请求NAT探测服务，收到对端的ServInfo信息后开始。
// @ip 服务端公网IP
// @serv 服务端连系信息
func (c *Client) Dial(ip netip.Addr, serv *stun.ServInfo) error {
	addr := &net.UDPAddr{
		IP:   ip.AsSlice(),
		Port: int(serv.Port),
	}
	// 及时结束
	c.dialok = make(chan struct{})

	key := [32]byte(serv.Skey)
	cnt := <-stun.ClientDial(c.dialok, c.conn, addr, ClientSN(serv.Sn32), Rnd16(serv.Token), &key)

	if cnt == 0 || cnt == stun.ClientDialCnt {
		return ErrDialUDP
	}
	return nil
}

// Dialled 是否已拨号成功。
// 已经获取公网地址是执行 STUN:Live 的前提条件。
func (c *Client) Dialled() bool {
	return c.paddr != nil
}

// Close 关闭客户端。
func (c *Client) Close() {
	close(c.Level)
	close(c.Live)
	close(c.UDPeer)
	c.conn.Close()
}
