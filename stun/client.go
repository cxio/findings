// STUN 客户端的一个实现。
// 向服务器请求 NAT 层级探测（STUN:Cone/Sym）和生存期探测（STUN:Live）。
//
// 用法（公共）：
// - 具体应用嵌入本实现的 Client 的一个实例（会自动启用服务监听。
// - 应用节点与Findings服务器建立 TCP 连接，向服务器发送 STUN:Cone/Sym/Live 请求。
// - 服务器回应 STUN:Cone/Sym/Live 请求。
// - 应用节点获得相关测试的初始信息（ServInfo），设置到 Client 实例中。
//
// STUN:Cone:
// - 应用节点向服务器的UDP监听地址拨号。
// - 服务器获得应用节点的UDP地址，从TCP链路发送回来。同时服务器会在UDP链路上发送探测包。
// - 应用节点从TCP链路获知自己的UDP地址，同时 Client 实例会在 UDP 链路上接收探测包。
// - 应用节点设置自身的UDP地址到 Client 实例中（SetConeAddr）。
// - 客户端（Client）服务进程综合判断自己的NAT层级，通过 NatLevel() 方法获取结果。
//
// STUN:Sym:
// 如果应用不能从 STUN:Cone 判断准确的NAT层级，则需向另一台服务器发送 STUN:Sym 请求。
// - 应用节点向服务器的UDP监听地址拨号。
// - 服务器获得应用节点的UDP地址，从TCP链路发送回来。
// - 应用节点获得自身UDP地址后，调用SetSymAddr，即可直接判断自己的NAT层级（P-RC|Sym）。
//
// STUN:Live:
// 需要在 STUN:Cone|Sym 探测后进行，即已经创建了一个UDP连接。
//
//////////////////////////////////////////////////////////////////////////////
//

package stun

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"time"
)

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

// Client 作为一个请求NAT探测的客户端。
// 其中conn为UDP主监听地址（STUN:Cone|Sym通讯），
// 以及STUN:Live探测中的旧地址（仅端口）。
type Client struct {
	Tester      chan STUNTester    // STUN 测试类型通知
	levCone     chan NatLevel      // NAT 层级通知（STUN:Cone）
	levSym      chan NatLevel      // NAT 层级通知（STUN:Sym）
	liveTime    chan time.Duration // NAT 生存期通知
	chkType     STUNTester         // 当前测试类型
	conn        *net.UDPConn       // UDP 主监听连接（NAT探测）
	paddr       *net.UDPAddr       // UDP公网地址（STUN:Cone）
	addr2       *net.UDPAddr       // 对比地址（STUN:Sym）
	raddr       *net.UDPAddr       // 服务器UDP监听地址（拨号时被更新）
	key         *[32]byte          // 对称加密密钥
	sn          ClientSN           // 当前序列号存储
	token       Rnd24              // 半个密钥种子
	dialok      chan struct{}      // UDP 拨号结束通知
	timeoutTest time.Duration      // 测试超时时间，超时后返回NAT_LEVEL_ERROR或-1
}

// 新建一个客户端。
// @conn 外部传入的客户端UDP监听连接
func newClient(conn *net.UDPConn) *Client {
	return &Client{
		conn:        conn,
		levCone:     make(chan NatLevel),
		levSym:      make(chan NatLevel),
		liveTime:    make(chan time.Duration, 1),
		timeoutTest: 30 * time.Second,
	}
}

// ListenClientUDP 创建客户端UDP监听。
// 监听本地所有IP地址，采用系统自动分配的端口。
// 用于本地受限节点。
func ListenClientUDP(ctx context.Context) (*Client, error) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 0,
	}
	conn, err := net.ListenUDP("udp", addr)

	if err != nil {
		return nil, err
	}
	// 创建并启动监听服务。
	return newClient(conn).serve(ctx), nil
}

// 启动本地监听&判断服务。
func (c *Client) serve(ctx context.Context) *Client {
	log.Println("Client UDP listen start:", c.conn.LocalAddr())

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case op := <-c.Tester:
				switch op {
				case STUN_CONE:
					c.levCone <- <-Resolve(ctx, c.paddr, c.conn, c.sn)
				case STUN_SYM:
					c.levSym <- Resolve2(c.addr2, c.paddr)
				case STUN_LIVE:
					// 新开一端口拨号
					conn2, err := net.DialUDP("udp", nil, c.raddr)
					if err != nil {
						log.Println("[Error] dialUDP to server failed.")
						break
					}
					// 约束：仅限于端口
					c.liveTime <- <-LivingTime(ctx, c.conn, conn2, c.raddr, c.token, c.sn, c.paddr.Port, c.key)
					conn2.Close()
				}
			}
		}
	}()

	return c
}

// SetTimeout 设置自定义的测试超时时间。
// 如果不设置，默认的超时时间为30秒。
// @d 超时时间，负值或零值无效
func (c *Client) SetTimeout(d time.Duration) {
	if d > 0 {
		c.timeoutTest = d
	}
}

// SetChkType 设置当前的测试类型。
func (c *Client) SetChkType(t STUNTester) error {
	if t < STUN_CONE || t > STUN_LIVE {
		return errors.New("invalid STUNTester type")
	}
	c.chkType = t
	return nil
}

// ChkType 获取当前的测试类型。
func (c *Client) ChkType() STUNTester {
	return c.chkType
}

// SetInfo 设置UDP基本信息。
// 在TCP链路收到服务器的ServInfo后，即时调用本方法。
// 内容包括：
// - 服务器UDP监听地址。
// - 服务器传递来的对称密钥。
// - 密钥因子（原样返回，方便服务端构造对称密钥）。
// - 当前事务序列号。
// @ip 服务器端IP
// @serv 服务器传递过来的信息集
func (c *Client) SetInfo(ip netip.Addr, serv *ServInfo) {
	c.raddr = &net.UDPAddr{
		IP:   ip.AsSlice(),
		Port: int(serv.Port),
	}
	key := [32]byte(serv.Skey)
	c.key = &key

	c.sn = ClientSN(serv.Sn48)
	c.token = Rnd24(serv.Token)
}

// Dial 从监听地址向对端UDP服务器拨号。
// 在从TCP链路请求NAT探测服务，收到对端的ServInfo信息后开始。
// 注意：
// 此时外部应当已调用SetInfo()设置必要的信息。
func (c *Client) Dial() error {
	// 简单预防性检查
	if c.raddr == nil {
		return errors.New("remote udp addr is empty")
	}
	// 用于及时结束
	c.dialok = make(chan struct{})

	cnt := <-ClientDial(c.dialok, c.conn, c.raddr, c.sn, c.token, c.key)

	if cnt == 0 || cnt == ClientDialCnt {
		return ErrDialUDP
	}
	// 友好记录
	log.Printf("Dial %d times for [%s]\n", cnt, c.raddr)

	return nil
}

// SetAddr 设置自身的UDP地址
// 在向服务器监听的UDP地址拨号后，获得服务器返回的信息后设置。
func (c *Client) SetAddr(addr *net.UDPAddr) {
	c.paddr = addr
	// 拨号结束通知
	close(c.dialok)
}

// SetCmpAddr 设置对比地址。
// 仅用于STUN:Sym探测，此时设置的是STUN:Cone请求时获得的地址。
// @addr 对比地址（STUN:Cone）
func (c *Client) SetCmpAddr(addr *net.UDPAddr) {
	c.addr2 = addr
}

// NatLevel 获取当前客户端的NAT层级。
// 需要先请求服务（STUN:Cone|Sym）、获得回应并拨号后才能取值。
// 此为阻塞调用，如果超时返回 NAT_LEVEL_ERROR。
func (c *Client) NatLevel() NatLevel {
	select {
	case level := <-c.levCone:
		return level
	case level := <-c.levSym:
		return level
	case <-time.After(c.timeoutTest):
		return NAT_LEVEL_ERROR
	}
}

// LiveTime 获取当前NAT生存期。
// 需要先请求服务（STUN:Live）并获得回应后， 测试函数再取值。
// 返回一个负值表示超时或错误。
func (c *Client) LiveTime() time.Duration {
	select {
	case live := <-c.liveTime:
		return live
	case <-time.After(c.timeoutTest):
		return -1 * time.Second
	}
}

// PubAddr 获取公网UDP地址。
func (c *Client) PubAddr() *net.UDPAddr {
	return c.paddr
}

// Dialled 是否已拨号成功。
// 已经获取公网地址是执行 STUN:Live 的前提条件。
func (c *Client) Dialled() bool {
	return c.paddr != nil
}

// Close 关闭客户端。
func (c *Client) Close() {
	close(c.Tester)
	close(c.levCone)
	close(c.levSym)
	close(c.liveTime)
	c.conn.Close()
}
