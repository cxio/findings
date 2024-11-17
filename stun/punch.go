package stun

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"
)

// 两个打洞方向常量
const (
	MasterDir = "master" // 主动方，先发送信息打洞，然后监听对端连入
	SlaveDir  = "slave"  // 从动方，直接拨号连接对端
)

var (
	// IP 解析错误
	ErrParseIP = errors.New("parse ip bytes failed")
	// 无法打洞错误
	ErrPunchDir = errors.New("invalid punch direction")
)

// Peer 节点信息
type Peer struct {
	IP    netip.Addr // 公网IP
	Port  int        // 公网监听/通讯端口
	Level NatLevel   // NAT 层级（0~3）
	Extra []byte     // 额外数据（如校验码）
}

// NewPeer 创建一个基础节点
func NewPeer(ip netip.Addr, port int, nat NatLevel, extra []byte) *Peer {
	return &Peer{IP: ip, Port: port, Level: nat, Extra: extra}
}

// UDPAddr 构造为UDP地址。
func (p *Peer) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   p.IP.AsSlice(),
		Port: p.Port,
	}
}

// Key 生成节点的键。
// 仅用IP和端口创建，会避免IPv4嵌入IPv6的不一致问题。
func (p *Peer) Key() string {
	addr := p.IP.Unmap()
	return netip.AddrPortFrom(addr, uint16(p.Port)).String()
}

// PunchDir 打洞方向
// 数组两个成员对应两个方向名称（master|slave）
type PunchDir [2]string

var punchDirs [4][4]PunchDir

// 打洞方向设定
// 为充分利用资源，低级别节点尽量充当 `master` 角色（Sym 例外）。
// 无定义的为不可互为打洞，方向值为空串。
func init() {
	// Sym -> Pub/FullC
	punchDirs[3][0] = PunchDir{SlaveDir, MasterDir}

	// P-RC <-> Pub/FullC | RC | P-RC
	punchDirs[2][0] = PunchDir{MasterDir, SlaveDir}
	punchDirs[2][1] = PunchDir{MasterDir, SlaveDir}
	punchDirs[2][2] = PunchDir{MasterDir, SlaveDir}

	// RC <-> Pub/FullC | RC | P-RC
	punchDirs[1][0] = PunchDir{MasterDir, SlaveDir}
	punchDirs[1][1] = PunchDir{MasterDir, SlaveDir}
	punchDirs[1][2] = PunchDir{SlaveDir, MasterDir}

	// Pub/FullC <-> Pub/FullC | RC | P-RC
	punchDirs[0][0] = PunchDir{SlaveDir, MasterDir}
	punchDirs[0][1] = PunchDir{SlaveDir, MasterDir}
	punchDirs[0][2] = PunchDir{SlaveDir, MasterDir}

	// Pub/FullC <- Sym
	punchDirs[0][3] = PunchDir{MasterDir, SlaveDir}
}

// PunchDir 评估设定打洞方向
// 根据NAT特性和充分利用资源的考虑，设定两个端点的打洞方向。
// @p1 打洞信息包1
// @p2 打洞信息包2
// @return 方向值，成员顺序对应传入的实参
func PunchingDir(p1, p2 *Peer) (*PunchDir, error) {
	pdir := punchDirs[p1.Level][p2.Level]

	if pdir[0] == "" {
		return nil, ErrPunchDir
	}
	return &pdir, nil
}

//
// 编解码函数
//////////////////////////////////////////////////////////////////////////////

// EncodePunch 编码打洞信息
// @dir 打洞方向（master|slave）
// @pun 打洞信息包
func EncodePunch(dir string, p *Peer) ([]byte, error) {
	buf := &Punchx{
		Dir:   dir,
		Ip:    p.IP.AsSlice(),
		Port:  int32(p.Port),
		Level: int32(p.Level),
		Token: p.Extra,
	}
	return proto.Marshal(buf)
}

// DecodePunch 解码打洞信息
// @data 编码数据
// @return1 打洞方向（master|slave）
// @return2 打洞信息包
func DecodePunch(data []byte) (string, *Peer, error) {
	buf := &Punchx{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return "", nil, err
	}
	addr, ok := netip.AddrFromSlice(buf.Ip)
	if !ok {
		return "", nil, ErrParseIP
	}
	return buf.Dir, NewPeer(addr, int(buf.Port), NatLevel(buf.Level), buf.Token), nil
}

// EncodePunchOne 编码定向打洞信息包
// 注意to可能为nil，此时为接收方登记入库逻辑。
// @app 应当端信息
// @to 打洞目标节点信息
// @expire 登记过期时长（秒数）
func EncodePunchOne(app *Peer, to *UDPInfo, expire int) ([]byte, error) {
	cli := &Punchx{
		Dir:   "",
		Ip:    app.IP.AsSlice(),
		Port:  int32(app.Port),
		Level: int32(app.Level),
		Token: app.Extra,
	}
	return proto.Marshal(&PunchOne{Client: cli, Target: to, Expire: int32(expire)})
}

// DecodePunchOne 解码定向打洞信息包
// 返回的string为目标节点的UDP地址串，作为索引查询键。
// 如果为登记场景，则该string为空串，无错。
// 注：
// 索引键中的IP会保证IPv6中嵌入的IPv4脱离出来。
// @return1 目标节点索引，空串表示登记
// @return2 节点自身UDP关联信息
func DecodePunchOne(data []byte) (string, *Peer, time.Duration, error) {
	buf := &PunchOne{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return "", nil, 0, err
	}
	// 客户端自身地址
	addr, ok := netip.AddrFromSlice(buf.Client.Ip)
	if !ok {
		return "", nil, 0, ErrParseIP
	}
	peer := NewPeer(
		addr,
		int(buf.Client.Port),
		NatLevel(buf.Client.Level),
		buf.Client.Token,
	)
	// 登记场景
	if buf.Target == nil {
		return "", peer, time.Duration(buf.Expire) * time.Second, nil
	}
	// 目标节点地址
	ip, ok := netip.AddrFromSlice(buf.Target.Ip)
	if !ok {
		return "", nil, 0, ErrParseIP
	}
	// 嵌入IPv6的IPv4会剥离。
	key := netip.AddrPortFrom(ip.Unmap(), uint16(buf.Target.Port))

	return key.String(), peer, 0, nil
}
