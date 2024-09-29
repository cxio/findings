package stun

import (
	"errors"
	"net"
	"net/netip"
	"strings"

	"google.golang.org/protobuf/proto"
)

// Peer 基础节点信息
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

// UDPAddr 构造为UDP地址。
func (p *Peer) TCPAddr() *net.TCPAddr {
	return &net.TCPAddr{
		IP:   p.IP.AsSlice(),
		Port: p.Port,
	}
}

// LinkPeer 关联节点
// 提供TCP监听地址和端口，或者UDP打洞需要的信息。
// 注意：
// Peer中的公网IP和端口，需与网络类型（tcp|udp）相对应。
type LinkPeer struct {
	*Peer          // 基础信息
	Network string // 支持的网络类型（tcp|udp）
}

// NewLinkPeer 创建一个应用端
func NewLinkPeer(net string, peer *Peer) *LinkPeer {
	return &LinkPeer{
		Peer:    peer,
		Network: strings.ToLower(net),
	}
}

// IP 解析错误
var ErrParseIP = errors.New("parse ip bytes failed")

// 无法打洞错误
var ErrPunchDir = errors.New("invalid punch direction")

// 两个打洞方向常量
const (
	MasterDir = "master" // 主动方，先发送信息打洞，然后监听对端连入
	SlaveDir  = "slave"  // 从动方，直接拨号连接对端
)

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

// EncodeAppinfo 应用端节点信息
// 用于应用端把自己的信息编码发送到服务器，寻求打洞协助（UDP)或注册自己的节点（TCP）。
// @kind 应用类型名
// @app 应用端信息包
func EncodeAppinfo(kind string, app *LinkPeer) ([]byte, error) {
	buf := &Appinfo{
		Kind:    kind,
		Network: app.Network,
		Ip:      app.IP.AsSlice(),
		Port:    int32(app.Port),
		Level:   int32(app.Level),
		Extra:   app.Extra,
	}
	return proto.Marshal(buf)
}

// DecodeAppinfo 解码打洞信息包
// @data 网络传输过来的已编码数据
// @return1 应用类型名
// @return2 应用端信息包
func DecodeAppinfo(data []byte) (string, *LinkPeer, error) {
	buf := &Appinfo{}

	if err := proto.Unmarshal(data, buf); err != nil {
		return "", nil, err
	}
	addr, ok := netip.AddrFromSlice(buf.Ip)
	if !ok {
		return "", nil, ErrParseIP
	}
	return buf.Kind, NewLinkPeer(buf.Network, NewPeer(addr, int(buf.Port), NatLevel(buf.Level), buf.Extra)), nil
}

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
