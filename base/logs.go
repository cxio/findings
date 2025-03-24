package base

import (
	"context"
	"log"

	"github.com/cxio/findings/cfg"
)

// 相应几个日志记录器
var (
	Log      *log.Logger // 通用记录
	LogPeer  *log.Logger // 有效连接节点历史
	LogDebug *log.Logger // 调试专用记录
)

// LogsInit 日志初始化。
// 创建3个基本日志记录器，外部直接使用即可。
// 当外部的上下文环节退出时，即关闭日志。
// @ctx 执行上下文
// @logs 日志存放根目录
func LogsInit(ctx context.Context, logs string) {
	// 主记录，含错误和警告
	log1, f1, err := cfg.CreateLoger(logs, cfg.LogFile, "")
	if err != nil {
		log.Fatalf("Failed to create log file %v\n", err)
	}
	go func() {
		<-ctx.Done()
		f1.Close()
	}()
	// 节点历史存留
	log2, f2, err := cfg.CreateLoger(logs, cfg.LogPeerFile, "[Peer] ")
	if err != nil {
		log.Fatalf("Failed to create log file %v\n", err)
	}
	go func() {
		<-ctx.Done()
		f2.Close()
	}()
	// 调试专用
	log3, f3, err := cfg.CreateLoger(logs, cfg.LogDebugFile, "[Debug] ")
	if err != nil {
		log.Fatalf("Failed to create log file %v\n", err)
	}
	go func() {
		<-ctx.Done()
		f3.Close()
	}()
	// 全局赋值
	Log, LogPeer, LogDebug = log1, log2, log3
}
