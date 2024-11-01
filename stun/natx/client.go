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
// 其中conn为主监听地址，用于STUN:Cone|Sym通讯，
// 以及STUN:Live的旧地址（端口）使用。
// 注记：
// 将 STUN:Cone|Sym 的通知分开更安全。
type Client struct {
	LevCone chan NatLevel      // NAT 层级通知（STUN:Cone）
	LevSym  chan NatLevel      // NAT 层级通知（STUN:Sym）
	Live    chan time.Duration // NAT 生存期通知
	UDPeer  chan *net.UDPAddr  // 客户端UDP地址通知
	Tester  chan STUNTester    // STUN 测试类型
	conn    *net.UDPConn       // UDP 主监听连接（NAT探测）
	paddr   *net.UDPAddr       // 对端回传的公网地址
	addr2   *net.UDPAddr       // 参考地址（STUN:Sym 对比用）
	raddr   *net.UDPAddr       // 服务器UDP监听地址（拨号时被更新）
	key     *[32]byte          // 对称加密密钥
	sn      ClientSN           // 当前序列号存储
	token   Rnd16              // 半个密钥种子
	dialok  chan struct{}      // UDP 拨号结束通知
}

// NewClient 新建一个Finder客户端。
// @conn 为客户端UDP监听连接
func NewClient(conn *net.UDPConn) *Client {
	return &Client{
		conn:    conn,
		LevCone: make(chan NatLevel),
		LevSym:  make(chan NatLevel),
		Live:    make(chan time.Duration),
		UDPeer:  make(chan *net.UDPAddr),
		paddr:   nil, // 由监听获取
		addr2:   nil, // 由外部设置
		dialok:  nil, // 由 Dial 赋值
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
					c.LevCone <- <-stun.Resolve(ctx, c.paddr, c.conn, c.sn)
				case STUN_SYM:
					c.LevSym <- stun.Resolve2(c.addr2, c.paddr)
				case STUN_LIVE:
					// 新开一端口拨号
					conn2, err := net.DialUDP("udp", nil, c.raddr)
					if err != nil {
						log.Println("[Error] dialUDP to server failed.")
						break
					}
					// 约束：仅限于端口
					c.Live <- <-stun.LivingTime(ctx, c.conn, conn2, c.raddr, c.token, c.sn, c.paddr.Port, c.key)
				}
			}
		}
	}()

	return c
}

// Dial 向对端UDP服务器拨号。
// 在请求NAT探测服务，收到对端的ServInfo信息后开始。
// 注意：
// 外部应当先调用SetInfo()设置基本数据。
func (c *Client) Dial() error {
	// 及时结束
	c.dialok = make(chan struct{})

	cnt := <-stun.ClientDial(c.dialok, c.conn, c.raddr, c.sn, c.token, c.key)

	if cnt == 0 || cnt == stun.ClientDialCnt {
		return ErrDialUDP
	}
	// 友好记录
	log.Printf("Dial %d times for [%s]\n", cnt, c.raddr)

	return nil
}

// SetInfo 设置UDP基本信息。
// 包括：
// - 服务器UDP监听地址
// - 服务器传递来的对称密钥
// - 当前事务序列号
// @ip 服务器端IP
// @serv 服务器传递过来的信息集
func (c *Client) SetInfo(ip netip.Addr, serv *stun.ServInfo) {
	c.raddr = &net.UDPAddr{
		IP:   ip.AsSlice(),
		Port: int(serv.Port),
	}
	key := [32]byte(serv.Skey)
	c.key = &key

	c.sn = ClientSN(serv.Sn32)
	c.token = Rnd16(serv.Token)
}

// PubAddr 获取公网UDP地址。
func (c *Client) PubAddr() *net.UDPAddr {
	return c.paddr
}

// SetCmpAddr 设置对比地址
// 即之前 STUN:Cone 请求获得的地址。
func (c *Client) SetCmpAddr(addr *net.UDPAddr) {
	c.addr2 = addr
}

// LinkPeer 提取关联节点。
// 专用于与其它UDP节点打洞和通讯，
// 这需要在用户已经获知当前节点的NAT层级之后才能使用。
// 注：
// 使用最后一次 STUN:Cone 或 STUN:Sym 探测的端口。
// 也即：用户需要首先探知自己的公网UDP地址。
// 提示：
// 如果用户已知自己节点的NAT层级，
// 获取公网UDP地址可以仅由简单的 STUN:Sym 请求实现。
//
// @nat  自身NAT层级
// @data 附带数据，可选
// @return 打洞关联节点
func (c *Client) LinkPeer(nat NatLevel, data []byte) *stun.Peer {
	if c.paddr == nil {
		return nil
	}
	ipp := c.paddr.AddrPort()

	return &stun.Peer{
		IP:    ipp.Addr(),
		Port:  int(ipp.Port()),
		Level: nat,
		Extra: data,
	}
}

// Dialled 是否已拨号成功。
// 已经获取公网地址是执行 STUN:Live 的前提条件。
func (c *Client) Dialled() bool {
	return c.paddr != nil
}

// Close 关闭客户端。
func (c *Client) Close() {
	close(c.LevCone)
	close(c.LevSym)
	close(c.Live)
	close(c.UDPeer)
	close(c.Tester)
	c.conn.Close()
}
