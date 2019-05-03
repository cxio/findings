// Package manage 服务管理。
// 用于授信地址对系统本身行为的控制：
//  - 软件升级。传递升级地址和Hash指纹，restart；
//  - 服务重启。restart；
//  - 服务关闭。stop；
//  - 载入新的配置（PRC热更新）；
//  - 载入新的范围节点配置；
//
package manage

import (
	"bytes"
	"errors"
	"io"

	"github.com/cxio/cxsuite/goes"
)

// OperCode 操作码
type OperCode int8

// 操作控制码。
const (
	Upgrade OperCode = 1 + iota
	Restart
	Stop
	Config
	Nodes
)

// Size sha256校验和字节数。
const Size = 32

var (
	errChksum   = errors.New("the file's md5 hash is not match")
	errDownload = errors.New("upgrade download was interrupted")
)

//
// CtrlMsg 控制消息
//
type CtrlMsg struct {
	Code   OperCode
	Path   string
	Chksum [Size]byte
	Config []byte
	Nodes  []byte
}

//
// Monitor 监视器。
// 获取传递来的必要的控制参数。
//
type Monitor interface {
	Listen(func() bool) (chan<- *CtrlMsg, error)
}

//
// Upgrades 升级管理器。
// 支持暂停、取消、重新下载指令；
// 支持哈希指纹校验文件。
//
type Upgrades struct {
	appName string      // conf.Config.AppName
	result  []byte      // 下载数据暂存
	cancel  func() bool // 外部退出下载判断
}

//
// Start 启动下载。
// 如果存在未下载完的临时文件，执行续传。
//
func (u *Upgrades) Start(url string) error {

}

//
// Cancel 取消升级。
// 含Clean逻辑，会清除下载的临时文件。
//
func (u *Upgrades) Cancel() {
	//
}

//
// Pause 暂停升级。
// 会保留未下载完的临时文件，待之后断点续传。
// （程序可能被关闭）
//
func (u *Upgrades) Pause() {

}

//
// Cached 下载是否已经缓存到本地。
// 可能文件并不完整，需要继续下载。
// 临时文件名：[appName].[url-md5]
//
func (u *Upgrades) Cached(url string) bool {

}

//
// CheckSum 检查下载数据指纹。
//
func (u *Upgrades) CheckSum(chksum [Size]byte) bool {

}

//
// Manage 管理器。
//
type Manage struct {
	Monitor
	Upgrade Upgrades
	stop    <-chan struct{}
}

//
// Restart 重启程序。
//
func (m *Manage) Restart() (string, bool) {

}

//
// Stop 关闭程序。
//
func (m *Manage) Stop() (string, bool) {

}

//
// Status 返回运行状态。
//
func (m *Manage) Status() (string, error) {

}

//
// Config 载入通用配置。
//
func (m *Manage) Config(r io.Reader) error {

}

//
// Nodes 载入范围节点配置。
//
func (m *Manage) Nodes(r io.Reader) error {

}

//
// 执行指令行为。
// 返回true表示控制操作需要结束监控。
//
func (m *Manage) process(msg *CtrlMsg, ch <-chan *Notice) bool {
	var s string
	var err error
	var exit bool

	switch msg.Code {
	case Upgrade:
		err = m.Upgrade.Run(goes.Canceller(m.stop))
		if err != nil {
			break
		}
		exit = true
	case Restart:
		if s, ok = m.Restart(); !ok {
			err = errors.New(s)
		} else {
			exit = true
		}
	case Stop:
		if s, ok = m.Stop(); !ok {
			err = errors.New(s)
		} else {
			exit = true
		}
	case Config:
		s, err = m.Config(bytes.NewBuffer(msg.Config))
	case Nodes:
		s, err = m.Nodes(bytes.NewBuffer(msg.Nodes))
	}
	ch <- &Notice{msg.Code, s, err}

	return exit
}

// Notice 对外通知。
type Notice struct {
	Code OperCode
	Text string
	err  error
}

//
// Serve 启动一个管理服务。
// 返回的通道用于获知管理执行的操作和反馈信息。
// 通道关闭表示监控关闭，一般程序需要关闭或重启。
//
func Serve(m Manage) <-chan *Notice {
	ch := make(chan *Notice, 1)
	go monitor(m, ch)
	return ch
}

// 监控服务。
func monitor(m Manage, ch chan<- *Notice) {
	cm, err := m.Listen(goes.Canceller(m.stop))
	if err != nil {
		ch <- &Notice{0, "", err}
	}
END:
	for {
		select {
		case <-m.stop:
			break END
		case msg := <-cm:
			if m.process(msg, ch) {
				break END
			}
		}
	}
	close(ch)
}
