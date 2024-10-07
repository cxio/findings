// Copyright (c) 2024 @cxio/blockchain
// Released under the MIT license
//////////////////////////////////////////////////////////////////////////////
//
// 用法：
// ---------------------------------------------------------------------------
//
// 加密：
// 服务器和客户端的TCP连接应使用安全链路，用来传输敏感的信息，其中就包含密钥。
// 密钥由服务器端构造，用来加密服务器与客户端之间的UDP数据。
//
// 密钥的构造：
//
//	Hash256(seed:32 + rnd:16) => [32]byte（密钥）
//
// 其中：
// - seed:32 为服务器当前运行时环境的随机数种子，32字节长。
// - rnd:16  为构造序列号时提取的随机序列，它不在最终的序列号中，但与序列号相关联。
// ---------------------------------------------------------------------------
//
// 序列号：
// ---------------------------------------------------------------------------
//
//////////////////////////////////////////////////////////////////////////////
//

// NAT 探测协助包（UDP）
package stun

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/cxio/findings/crypto/utilx"
)

// NatLevel NAT层级
type NatLevel int

// NAT 分层定义
const (
	NAT_LEVEL_NULL   NatLevel = iota // 0: Public | Public@UPnP | Full Cone
	NAT_LEVEL_RC                     // 1: Restricted Cone (RC)
	NAT_LEVEL_PRC                    // 2: Port Restricted Cone (P-RC)
	NAT_LEVEL_SYM                    // 3: Symmetric NAT (Sym) | Sym UDP Firewall
	NAT_LEVEL_PRCSYM                 // 4: P-RC | Sym
	NAT_LEVEL_ERROR                  // 5: UDP不可用，或探测错误默认值
)

// UDPSendi 服务器UDP发送方式
type UDPSendi int

// UDP-Listen 发送操作
const (
	UDPSEND_LOCAL   UDPSendi = iota // UDP 发送：本地
	UDPSEND_NEWPORT                 // UDP 发送：新端口
	UDPSEND_NEWHOST                 // UDP 发送：新主机
)

// LenSN 序列号长度。
// 格式：16 + 16 = 32
const LenSN = 32

// ClientSN 客户端序列号类型
// [:16] 一个随机字节序列，是构造序列号的种子之一。
// [16:] 两个种子计算的Sum256结果的局部（后段）。
type ClientSN [LenSN]byte

// Rnd16 16字节随机序列
type Rnd16 [16]byte

// Notice 协作通知
// 用于本地服务器 TCP <=> UDP 间协作探查。
// Reply：
// - true 发送成功
// - false 发送失败
type Notice struct {
	Op    UDPSendi     // UDP发送指示
	Addr  *net.UDPAddr // 目标客户端地址
	SN    ClientSN     // 待发送内容
	Reply chan bool    // 结果回报通道
}

// NewNotice 创建一个协作通知。
func NewNotice(op UDPSendi, addr *net.UDPAddr, sn ClientSN, rep chan bool) *Notice {
	return &Notice{
		Op:    op,
		Addr:  addr,
		SN:    sn,
		Reply: rep,
	}
}

// Client 客户端基本信息
type Client struct {
	Addr *net.UDPAddr
	SN   ClientSN
}

const (
	timeoutReadUDP = time.Second * 10 // 普通UDP读取超时
	timeoutLiveNAT = time.Second * 7  // LiveNAT包读取超时
)

// 三个UDP消息置位标记
const (
	bitListen  uint8 = 1 << iota // Listen UDP
	bitNewPort                   // NewPort UDP
	bitNewHost                   // NewHost UDP
)

// GenerateClientSN 创建一个IP特定的序列号
// 包含特定的结构，服务器端可以直接关联对端IP计算验证（VerifySN）。
// 结构：
// IP + (seed:32 + rand:16) => data
// seed 为服务器端固定种子值，每次启动后随机构造。
// 生成：
// - Hash(data) => hash
// - rand:16 + hash[16:32] => 序列号（sn）
// - hash[:16] => Rnd16
// 即：
// - 对外暴露16字节的随机序列，以及哈希结果的后半段。
// - 隐藏服务器端种子seed，以及哈希结果的前半段（Rnd16 另有用途）。
// 参数：
// @seed 随机数种子，服务器启动后自动生成，运行期间固定不变
// @ip 对端节点的公网IP，通常从TCP连接获取
// @return1 匹配对端的一个随机序列号（锁定对端IP）
// @return2 哈希结果的前段未用16字节，用于隐式密码种子
//
// 注记：
//   - return2 可以用来和 seed 组合成密钥（Sum256后），提供给客户端加密UDP数据。
//     这在客户端初次发送UDP信息和 STUN:Live 探测中有用。
//   - return2 也可以用来作为map的键，引用提出请求的客户端的TCP连接。
//     这在服务器回报客户端的UDP地址时有用。
func GenerateClientSN(seed [32]byte, ip netip.Addr) (ClientSN, Rnd16, error) {
	// rand:16
	sn16, err := utilx.GenerateToken(16)
	if err != nil {
		return ClientSN{}, Rnd16{}, err
	}
	buf := make([]byte, 32+16)

	copy(buf[:32], seed[:]) // [0:32] seed:32
	copy(buf[32:], sn16)    // [32:48] rand:16

	hash := utilx.HashMAC_ip(buf, ip)
	rest := Rnd16(hash[:16])

	copy(hash[:16], sn16) // rand:16 + hash2

	return ClientSN(hash), rest, nil
}

// VerifySN 验证序列号是否正确。
// 环境：
// 序列号的发送是在TCP链路上，因此生成采用的IP是从TCP连接上获取。
// 序列号的验证是在UDP链路上，因此验证针对的IP是从UDP连接上获取。
// 因此需要合理假设：一个NAT内的客户端同一时间发送的TCP和UDP会有同一个源IP地址。
// 说明：
// - seed 服务器的随机数种子，服务器启动后即固定不变。
// - ip 对端节点的公网IP，从当前UDP连接上获取（其应当与TCP链路上相同）。
// - sn 对端节点随UDP数据包发送过来的序列号。
// 验证：
// 根据上面生成函数的结构说明进行计算：
// - sn[:16] => rand:16
// - seed:32 + rand:16 + ip:xxx => data
// - Sum256(data) => hash
// 结果：
// @return1: sn[16:] ?= hash[16:]
// @return2: 提取的哈希结果的前段16字节
func VerifySN(seed [32]byte, ip netip.Addr, sn ClientSN) (bool, Rnd16) {
	buf := make([]byte, 32+16)

	copy(buf[:32], seed[:]) // [0:32] seed:32
	copy(buf[32:], sn[:16]) // [32:48] rand:16

	hash := utilx.HashMAC_ip(buf, ip)

	// 常量比较时间，避免侧信道攻击seed
	return hmac.Equal(sn[16:], hash[16:]), Rnd16(hash[:16])
}

// GenerateSnKey 创建序列号关联密钥
// 该密钥用来加密客户端发送给服务器的自身的另一个UDP地址。
// 这由服务器调用，结果密钥通过原有TCP链路发送给客户端（和序列号等信息一起）。
// 注记：
// 服务器验证客户端的UDP消息时，即时生成密钥即可。
// @seed 服务器端随机种子
// @rest 序列号验证后的第二个返回值
// @return 地址加密密钥
func GenerateSnKey(seed [32]byte, rest Rnd16) [32]byte {
	buf := make([]byte, 32+16)

	copy(buf, seed[:])
	copy(buf[32:], rest[:])

	return sha256.Sum256(buf)
}

// ListenUDP STUN 监听服务。
// 与TCP链路一起配合，接收客户端的初始拨号，提取其公网地址。
// 向TCP链路提供客户端的基本信息。
// @ctx 上下文控制
// @port 本地UDP监听端口
// @seed 服务器随机数种子
// @nch 协作通知渠道
// @return 客户端的信息告知通道
func ListenUDP(ctx context.Context, port int, seed [32]byte, nch chan *Notice) <-chan *Client {
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		// 致命错误
		log.Fatalln("[Error] listening:", err)
	}
	defer conn.Close()

	log.Println("STUN service started on", addr.Port)

	ch := make(chan *Client)

	go func() {
		defer close(ch)

		// 仅加密了序列号
		// 16 + (32 + 28) = 76
		buf := make([]byte, 100)

		for {
			select {
			case <-ctx.Done():
				return

			case ntc := <-nch:
				switch ntc.Op {
				// 本地服务器委托发送
				case UDPSEND_LOCAL:
					err = ListenSend(conn, ntc.Addr, ntc.SN)
				case UDPSEND_NEWPORT:
					err = NewPortSend(ntc.Addr, ntc.SN)

				// 应为外部服务器委托至此
				case UDPSEND_NEWHOST:
					err = NewHostSend(ntc.Addr, ntc.SN)
				}
				ntc.Reply <- err == nil
				close(ntc.Reply)

			default:
				// 读取超时限制
				conn.SetReadDeadline(time.Now().Add(timeoutReadUDP))

				n, clientAddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					log.Println("[Error] reading from UDP:", err)
					continue
				}
				// buf[:16] 为服务器TCP给客户端的半个种子
				// buf[16:76] 为序列号的密文
				key := GenerateSnKey(seed, Rnd16(buf[:16]))

				// buf后段为序列号密文
				sn, err := DecryptSN(buf[16:n], &key)
				if err != nil {
					log.Println("Decrypt client's SN data is failed.")
					continue
				}

				// 验证序列号
				// 冗余。实际上如果key能正常解密即已合法。
				ok, _ := VerifySN(seed, clientAddr.AddrPort().Addr(), sn)
				if !ok {
					log.Println("Verify client's SN failed.")
					continue
				}
				ch <- &Client{Addr: clientAddr, SN: sn}
			}
		}
	}()

	return ch
}

// ClientDial 客户机向服务器初始拨号发送UDP消息。
// 客户端在获得服务器UDP监听地址和序列号以及密钥后执行。
// 环境：
// - 适用于尚未建立过UDP链路，不知道网络是否友好UDP时。
//
// RFC3489：冗余多次发送，最多9次。
// 间隔时间（ms）：100, 200, 400, 800, 1600, 1600, 1600, 1600, 1600 结束
// 累计时长（ms）：100, 300, 700, 1500, 3100, 4700, 6300, 7900, 9500 超时
//
// @ctx 当客户端从TCP连接收到回应后，ctx通知取消发送
// @conn 客户端的UDP监听连接，会在此连接上发送消息
// @serv 服务器UDP监听地址
// @sn 序列号（当前事务ID），从服务器端获得，原样发送
// @rnd 半个随机数种子
// @key 对称加密/解密密钥
// @return 一个通道，告知实际发送的次数
func ClientDial(ctx context.Context, conn *net.UDPConn, serv *net.UDPAddr, sn ClientSN, rnd Rnd16, key *[32]byte) <-chan int {
	var cnt int
	ch := make(chan int)
	waitting := time.Millisecond * 100
	waitEnd := time.Millisecond * 1600

	go func() {
		defer close(ch)
		defer func() { ch <- cnt }()

		data, err := EncryptSN(sn, key)
		// 致命错误
		if err != nil {
			log.Fatal("Encrypt client's SN failed.")
			return
		}
		// rnd + Encrypted SN
		data = append(rnd[:], data...)

		// 最多尝试9次，RFC3489
		for i := 0; i < 9; i++ {
			select {
			case <-ctx.Done():
				return

			case <-time.After(waitting):
				// 短消息2秒足矣
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))

				_, err := conn.WriteToUDP(data, serv)
				if err != nil {
					// 超时重试
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					return
				}
				if waitting < waitEnd {
					waitting *= 2
				}
				cnt++
			}
		}
	}()
	return ch
}

// ListenSend 服务器从监听连接发送UDP消息。
// 通讯的本地端口为监听器端口，不会新建一个端口。
// 此为服务器的正常回应，UDP链路已通。最多尝试3次（共3个数据包）。
// @conn 服务器Listen创建的UDP监听连接
// @raddr 目标客户端的UDP地址
// @sn 客户序列号。首字节会设置标志，表示Listen发送
func ListenSend(conn *net.UDPConn, raddr *net.UDPAddr, sn ClientSN) error {
	// 安全性：
	// 尽量保留原始信息，仅修改低3位，避免显著特征
	sn[0] = (sn[0] & 0b11111_000) | bitListen

	return redunSendUDP(conn, raddr, sn[:], 3)
}

// NewPortSend 服务器用一个新端口发送UDP消息。
// 由协助服务器自己发送，测试对方是否为 RC NAT 类型。
// 对方：
// - 收到 => RC
// - 未收到 => P-RC 或 Sym。
// @raddr 目标客户端的UDP地址
// @sn 客户序列号，首字节会设置标志，表示NewPort发送
func NewPortSend(raddr *net.UDPAddr, sn ClientSN) error {
	sn[0] = (sn[0] & 0b11111_000) | bitNewPort
	return dialSend(raddr, sn[:])
}

// NewHostSend 新服务器发送UDP消息。
// 由收到 NewHost 请求的节点执行发送（新主机自然为一个新IP）。
// 对方：
// - 收到 & 1.N   => FullC 类型
// - 收到 & 1.Y   => 公网之上（Open Internet）
// - 未收到 & 1.Y => Sym UDP Firewall
// - 未收到 & 1.N => P-RC | Sym 类型（注：也含RC，但RC已由3.判断出来）
// @raddr 目标客户端的UDP地址
// @sn 客户序列号，首字节会设置标志，表示NewHost发送
func NewHostSend(raddr *net.UDPAddr, sn ClientSN) error {
	sn[0] = (sn[0] & 0b11111_000) | bitNewHost
	return dialSend(raddr, sn[:])
}

// Resolve 解析NAT类型。
// 根据收到的消息综合判断本客户端的NAT类型。
// 注：在客户端收到服务器从TCP链路的回复之后即可开始。
// @ctx 外部上下文控制
// @paddr 客户端UDP公网地址
// @conn 客户端UDP监听地址
// @sn 客户原始序列号（未设置前端标志字符）
// @return 一个通道，告知分析结果
func Resolve(ctx context.Context, paddr *net.UDPAddr, conn *net.UDPConn, sn ClientSN) <-chan NatLevel {
	ch := make(chan NatLevel)
	chsn := make(chan ClientSN)
	done := make(chan struct{})

	buf := make([]byte, 32)
	pleq := equalAddrUDP(paddr, conn.LocalAddr().(*net.UDPAddr))

	// [0] - Listen
	// [1] - NewPort
	// [2] - NewHost
	var udp3x [3]bool

	// 持续读取UDP消息进程
	// 有3项UDP消息需要读取：Listen, NewPort, NewHost
	// 因为存在无法收到信息的情况且数据报可能重复，不用计数的方式决定退出。
	go func() {
		defer close(chsn)

		for {
			select {
			case <-ctx.Done():
				return
			// 足够的时长
			case <-time.After(timeoutReadUDP):
				return
			case <-done:
				return // 特例（Pub/FullC）
			default:
				n, _, err := conn.ReadFromUDP(buf)

				// 尽可能获取
				if err != nil {
					log.Println("[Error] reading from UDP:", err)
					continue
				}
				if n != LenSN {
					log.Printf("[Error] reading UDP sn is not %d bytes.", LenSN)
					continue
				}
				chsn <- ClientSN(buf[:LenSN])
			}
		}
	}()

	// 状态赋值&判断进程
	go func() {
		defer close(ch)
		defer close(done)
		defer func() { ch <- coneLevel(paddr, pleq, udp3x) }()

		for {
			select {
			case <-ctx.Done():
				return
			case sn2, ok := <-chsn:
				if !ok {
					return // 已关闭
				}
				flag := sn[0]
				// 首字节恢复
				sn2[0] = sn[0]

				if sn2 != sn {
					log.Println("The serial number is invalid.")
					continue
				}
				// 低3位取值
				switch flag & 0b00000_111 {
				case bitListen:
					udp3x[0] = true
				case bitNewPort:
					udp3x[1] = true
				case bitNewHost:
					udp3x[2] = true
				}
				// 特例快速完成：Pub/FullC
				if udp3x[2] && udp3x[1] && udp3x[0] {
					return
				}
			}
		}
	}()

	return ch
}

// STUN:Sym 简单判断NAT类型。
// 仅在 STUN:Cone 主服务之后使用，判断为 P-RC | Sym 两者之一。
// 如果 Resolve 调用返回 NAT_LEVEL_PRCSYM 则需使用此函数。
// 注：无阻塞。
// @paddr1 主服务时获取的客户端公网地址
// @paddr2 本次副服务时获取的客户端公网地址
func Resolve2(paddr1, paddr2 *net.UDPAddr) NatLevel {
	if equalAddrUDP(paddr1, paddr2) {
		return NAT_LEVEL_PRC
	}
	return NAT_LEVEL_SYM
}

// LivingTest 客户端NAT映射生命期探测（单次）。
// 客户端用一个新的UDP端口发送信息包（NAT会新建一个映射）。
// 此测试是在客户端NAT探测之后执行，已经验证NAT是否已支持UDP链路。
// 因此只发送2个冗余数据包。
// 数据：
// - 当前测试批次、序列号。合并在一起共33字节。
// - 服务器回复的目标UDP地址。
// 行为：
// 1. 在原来的监听端口号上监听回复。
// 2. 在新发送消息的连接上读取回复。
// 判断：
// - 在 1. 上读取到回复，表示NAT映射没有改变。返回true
// - 在 2. 上读取到回复，表示NAT映射已经改变（复用了之前的端口）。返回false
// - 如果都没有收到回复，表示NAT映射已经完全改变。返回false
// 注记：
// 这仅是执行单次测试，最终的生命期计算需要多次探测。
// 用户可以自己设计时间间隔策略，但也可以直接使用下面的LivingTime探测函数。
//
// @ctx 上下文环境控制
// @conn 客户端UDP原监听连接
// @con2 客户端新拨号的连接，在此连接上发送探测
// @raddr 服务器UDP监听地址，拨号目标
// @cnt 发送批次计数
// @sn 原始序列号，用于对比验证
// @addr 已加密地址密文
// @key 对称加密/解密密钥，用于验证服务器回应的序列号
// @return 是否已经改变
func LivingTest(ctx context.Context, conn, conn2 *net.UDPConn, raddr *net.UDPAddr, cnt uint8, sn ClientSN, addr []byte, key *[32]byte) (bool, error) {
	// 探测消息
	msg, err := EncodeLiveNAT(cnt, sn, addr)
	if err != nil {
		return false, err
	}
	// 冗余发送 2 次
	go redunSendUDP(conn2, raddr, msg, 3)

	// 监听等待……
	// 单次监听等待时间不会超过timeoutReadUDP设置。
	// 通常 timeoutLiveNAT <= timeoutReadUDP，使得可以多次读取尝试。
	for {
		select {
		case <-ctx.Done():
			return false, nil

		case <-time.After(timeoutReadUDP):
			return false, nil

		case buf := <-readFromUDP(conn, timeoutLiveNAT, 64):
			if buf == nil {
				return false, errors.New("read UDP is failed")
			}
			n, sn2, err := DecryptSn33(buf, key)
			if err != nil {
				// 依然继续，避免有意破坏
				log.Println("[Error] decrypt client's [count+SN]:", err)
				continue
			}
			// 批次或序列号不符
			// 可能是前批遗留、干扰或攻击，忽略
			if n != cnt || sn != sn2 {
				continue
			}
			return true, nil

		case buf := <-readFromUDP(conn2, timeoutLiveNAT, 64):
			if buf == nil {
				return false, errors.New("read UDP is failed")
			}
			n, sn2, err := DecryptSn33(buf, key)
			if err != nil {
				log.Println("[Error] decrypt client's [count+SN]:", err)
				continue
			}
			// 同上杂讯忽略。
			if n != cnt || sn != sn2 {
				continue
			}
			return false, nil
		}
	}
}

// LivingTime 测试探查NAT映射生命期。
// 按逐渐增加的时间间隔持续调用LivingTest测试，
// 最后一次成功的时间间隔即是NAT生命期（近似值）。
// 时间间隔：
// 从30秒开始，每次间隔时间增加14秒，即：30s, 44s, 58s, 72s ...
// 使用：
// 客户端在原连接上探知了自己的UDP公网地址和NAT类型后，即可开始此流程。
// 这里初次的探测包会在30秒之后才发送。
//
// 服务器端：
// - 一个专门的端口监听并读取LiveNAT数据。
// - 如果接收的数据长度大于33字节，这后续部分为加密的地址信息。
// - 如果接收的数据长度小于等于33字节，则忽视（客户端维持新端口活跃的消息，无需理睬）。
// - 验证序列号、提取隐藏序列构造密钥解密地址，然后向该地址发送回应包。
// - 回应包仅需包含原数据前33字节（批次+序列号），加密传送，客户端据此验证回复。
// - 这是一种通用设计，服务器无需存储和分辨对端。
//
// @ctx 上下文环境控制（如超时取消）
// @conn 客户端UDP原监听连接，会同时在此连接上监听回复
// @conn2 客户端新拨号的连接，在此连接上持续发送探测
// @raddr 服务器UDP监听地址，新拨号的目标
// @laddr 本地UDP目标地址（服务器发送的目标）
// @sn 序列号，从服务器端获得，原样发送和接收（服务端原样返回）
// @return 一个通道，告知结果（零值无意义）
func LivingTime(ctx context.Context, conn, conn2 *net.UDPConn, raddr, laddr *net.UDPAddr, sn ClientSN, key *[32]byte) <-chan time.Duration {
	ch := make(chan time.Duration)
	done := make(chan struct{})
	incrTime := 14 * time.Second      // 每次探测递增间隔时间
	waitTime := 30 * time.Second      // 初始间隔时间
	maxWaitTime := 10 * time.Minute   // 最大间隔时间（10分钟）
	checkInterval := 30 * time.Second // 维持新连接活性

	// 维持新连接活动状态
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			default:
				// 立即发送
				_, err := conn2.WriteToUDP([]byte("hello ping"), raddr)
				if err != nil {
					log.Println("Error write UDP with hello ping.")
				}
				time.Sleep(checkInterval)
			}
		}
	}()

	// 执行探测……
	go func() {
		defer close(ch)
		defer close(done)
		defer func() { ch <- waitTime }()

		// 发送批次
		var cnt uint8 = 1

		addrx, err := EncryptAddr(laddr, key)
		if err != nil {
			return
		}
		for waitTime <= maxWaitTime {
			select {
			case <-ctx.Done():
				return
			case <-time.After(waitTime):
				live, err := LivingTest(ctx, conn, conn2, raddr, cnt, sn, addrx, key)
				if err != nil {
					log.Println("[Error] test NAT lifetime:", err)
					return
				}
				if !live {
					// 回到上次间隔，完成
					waitTime -= incrTime
					return
				}
				cnt++
				waitTime += incrTime
			}
		}
	}()

	return ch
}

// LiveListen 启动NAT生命期探测服务
// 作为一个单独的服务存在，服务器仅需根据简单的规则回应即可。
// 即并不与NAT类型探测（STUN:Cone/Sym）服务合并在一起。
// 使用者：服务器
// @ctx 上下文控制
// @seed 服务器随机数种子
// @addr 本地监听地址
func LiveListen(ctx context.Context, port int, seed [32]byte) {
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		// 致命错误
		log.Fatalln("[Error] listening:", err)
	}
	defer conn.Close()

	log.Println("NAT lifetime detection service started on", addr.Port)

	// (批次+序列号)+加密(ip+port)
	// (1 + 32) + (16 + 2) + 28 = 79
	buf := make([]byte, 100)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Println("[Error] reading from UDP:", err)
				continue
			}
			// 非Lifetime探测消息，忽略
			if n <= 33 {
				// 仅简单输出（非日志）
				fmt.Println("NAT livetime test data ignored.")
				continue
			}

			cnt, sn, data, err := DecodeLiveNAT(buf[:n])
			if err != nil {
				log.Println("Decode liveNAT data is failed.")
				continue
			}
			// 先验证序列号
			ok, rnd := VerifySN(seed, clientAddr.AddrPort().Addr(), sn)
			if !ok {
				log.Println("Verify client's SN failed.")
				continue
			}
			// 即时构建密钥
			// 会与服务器发送给客户端的密钥相同。
			key := GenerateSnKey(seed, rnd)

			toAddr, err := DecryptAddr(data, &key)
			if err != nil {
				log.Println("Decrypt client's UDP addr failed.")
				continue
			}
			log.Printf("Received NAT lifetime detection from %s\n", clientAddr.String())

			// 非阻塞发送
			go liveResponseUDP(conn, toAddr, cnt, sn, &key)
		}
	}
}

//
// 私有辅助部分
//////////////////////////////////////////////////////////////////////////////
//

// 比较两个UDP地址相等性。
func equalAddrUDP(addr1, addr2 *net.UDPAddr) bool {
	if addr1 == nil || addr2 == nil {
		return addr1 == addr2
	}
	return addr1.IP.Equal(addr2.IP) && addr1.Port == addr2.Port
}

// dialSend 拨号发送UDP消息。
// 会自动创建一个新的端口号，最多尝试3次（3个数据包）。
// 适用：NewPort/NewHost 协助。
// 使用者：服务器
func dialSend(raddr *net.UDPAddr, data []byte) error {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 最多3次尝试。
	return redunSendUDP(conn, raddr, data, 3)
}

// 综合判断NAT类型。
// 仅限于 STUN:Cone 主服务的判断，P-RC/Sym 待定。
// @paddr 客户端公网地址
// @eq 客户端公网地址与本地地址是否相同
// @u3x 服务器发送的3级UDP信号收到状态
func coneLevel(paddr *net.UDPAddr, eq bool, u3x [3]bool) NatLevel {
	if !u3x[0] {
		log.Println(paddr, "UDP network was blocked.")
		return NAT_LEVEL_ERROR
	}
	if u3x[2] {
		// FullC | Public | Public@UPnP
		return NAT_LEVEL_NULL
	} else if eq {
		log.Println(paddr, "in Sym UDP Firewall.")
		return NAT_LEVEL_SYM
	}
	if u3x[1] {
		return NAT_LEVEL_RC
	}
	return NAT_LEVEL_PRCSYM // P-RC | Sym
}

// 冗余发送UDP数据报（短间隔连续）。
// 由于UDP的不可靠性，会冗余发送几次数据包（共max次尝试）。
// 间隔时间：100ms, 200ms, 300ms, ...
// 采用普通方式发送，对客户端没有特别要求。
// 环境：
// - 通常用于已经成功发送过UDP消息的链路。
// - 或服务器向可接收UDP数据报的客户端发送消息。
// 返回值：
// - 如果出错且不是超时错误，立即退出发送循环。
// - 超时错误会尝试重发，但总共最多尝试max次。
// - 若已成功发送2次，则视为成功。
// - 若前面几次都为超时错误，最后一次成功，也视为成功（返回nil）。
// @conn 一个UDP连接（DialUDP | ListenUDP 创建）
// @raddr 目标的UDP地址
// @data 客户端（目标）数据
// @return 成功返回nil，返回错误表示失败。
func redunSendUDP(conn *net.UDPConn, raddr *net.UDPAddr, data []byte, max int) error {
	var err error
	var cnt int

	// 阻塞式
	for i := 1; i <= max; i++ {
		// 短消息2秒足够
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))

		_, err = conn.WriteToUDP(data, raddr)
		if err != nil {
			// 超时重试
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}
		cnt++
		<-time.After(time.Millisecond * time.Duration(100*i))
	}
	// 成功2次也通过
	if cnt > 1 {
		return nil
	}
	return err // error or nil
}

// 单次发送UDP数据
// 如果出现超时错误，容许多次尝试。但成功一次即可。
// @conn 一个UDP连接
// @raddr 接收消息的目标地址
// @data 发送的数据
// @max 最多尝试的次数
func onceSendUDP(conn *net.UDPConn, raddr *net.UDPAddr, data []byte, max int) error {
	var err error

	// 阻塞式
	for i := 0; i < max; i++ {
		// 写入超时2秒足够
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))

		_, err = conn.WriteToUDP(data, raddr)
		if err != nil {
			// 仅超时重试
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				time.Sleep(200 * time.Millisecond)
				continue
			}
		}
		break // 成功或非超时错误
	}
	return err // error or nil
}

// NAT 生命期探测回应（服务器）
// 会对客户端传递过来的批次和序列号明文加密传送。
// @conn 一个UDP连接
// @raddr 接收消息的目标地址
// @cnt 原批次计数
// @sn 客户端序列号
// @key 对称加密密钥
func liveResponseUDP(conn *net.UDPConn, raddr *net.UDPAddr, cnt uint8, sn ClientSN, key *[32]byte) {
	// 加密（批次+序列号）
	response, err := EncryptSn33(cnt, sn, key)
	if err != nil {
		// 致命错误
		log.Fatalln("[Error] encrypt client's [count+SN]:", err)
	}
	// 容许3次写入超时
	err = onceSendUDP(conn, raddr, response, 3)
	if err != nil {
		log.Println("[Error] writing encrypted [count+SN] to UDP:", err)
	}
}

// 读取UDP数据。
// 返回的通道传递读取的数据，如果读取失败，通道会关闭（无值传递）。
// 读取超时也视为失败。
// 服务器端仅需回送客户端提供的序列号即可。
// @conn 读取的UDP链路
// @long 超时时间
// @size 读取缓冲区大小
func readFromUDP(conn *net.UDPConn, long time.Duration, size int) <-chan []byte {
	ch := make(chan []byte)

	go func() {
		defer close(ch)

		// 数据仅包含序列号
		buf := make([]byte, size)
		conn.SetReadDeadline(time.Now().Add(long))

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("[Error] reading from UDP:", err)
			return
		}
		ch <- buf[:n]
	}()
	return ch
}

//
// 专用辅助部分
//////////////////////////////////////////////////////////////////////////////
//

// EncryptAddr 加密网络地址
// 与EncodeLiveNAT配合使用，在其之前加密地址信息。
// 使用者：客户端
func EncryptAddr(addr *net.UDPAddr, key *[32]byte) ([]byte, error) {
	baddr, err := addr.AddrPort().MarshalBinary()
	if err != nil {
		return nil, err
	}
	return utilx.Encrypt(baddr, key)
}

// DecryptAddr 解密网络地址数据
// 与DecodeLiveNAT配合使用，在服务器验证序列号合法之后，解密提取目标地址。
// 使用者：服务器
func DecryptAddr(data []byte, key *[32]byte) (*net.UDPAddr, error) {
	data, err := utilx.Decrypt(data, key)
	if err != nil {
		return nil, err
	}
	var ipp netip.AddrPort

	if err = ipp.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return net.UDPAddrFromAddrPort(ipp), nil
}

// EncryptSn33 加密批次&序列号
// 服务器端回送LiveNAT消息时加密。简单数据无需protoBuf编码。
// 安全性：
// 客户端发送的序列号是明文的，因为服务器需要明文序列号提取密钥构造因子。
// 服务器回送序列号时进行加密，使得明文序列号是单向的，可有效避免监听。
// 使用者：服务器
func EncryptSn33(cnt uint8, sn ClientSN, key *[32]byte) ([]byte, error) {
	buf := [33]byte{cnt}
	return utilx.Encrypt(append(buf[:1], sn[:]...), key)
}

// DecryptSn33 解密批次&序列号
// 由客户端解密服务器回应的消息，提取批次和序列号。
// 使用者：客户端
func DecryptSn33(data []byte, key *[32]byte) (uint8, ClientSN, error) {
	sn33, err := utilx.Decrypt(data, key)
	if err != nil {
		return 0, ClientSN{}, err
	}
	return sn33[0], ClientSN(sn33[1:]), nil
}

// EncryptSN 加密序列号
// 用于客户端向服务器回送UDP信息以发现自己的公网地址。
// 使用者：客户端
func EncryptSN(sn ClientSN, key *[32]byte) ([]byte, error) {
	return utilx.Encrypt(sn[:], key)
}

// DecryptSN 解密序列号
// 由服务器读取、解密和验证，并获取客户端的公网地址。
// 使用者：服务器
func DecryptSN(data []byte, key *[32]byte) (ClientSN, error) {
	sn32, err := utilx.Decrypt(data, key)
	if err != nil {
		return ClientSN{}, err
	}
	return ClientSN(sn32), nil
}
