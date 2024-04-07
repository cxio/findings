// findings 主程序，包含客户端和服务器逻辑。
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// Config 结构体用于存储配置信息
type Config struct {
	ServerPort int `json:"server_port"`
}

func main() {
	// 读取配置文件
	config, err := readConfig()
	if err != nil {
		fmt.Println("Error reading config:", err)
		return
	}

	// 启动服务器
	go startServer(config.ServerPort)

	// 启动客户端
	startClient()
}

// 读取配置文件
func readConfig() (Config, error) {
	var config Config

	// 获取当前用户的家目录
	usr, err := os.UserHomeDir()
	if err != nil {
		return config, err
	}

	// 构建配置文件路径
	// ~/.findings/config.json
	configPath := filepath.Join(usr, ".findings", "config.json")

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(data, &config)
	return config, err
}

// 启动服务器
func startServer(port int) {
	fmt.Printf("Starting server on port %d...\n", port)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleClient(conn)
	}
}

// 处理客户端连接
func handleClient(conn net.Conn) {
	defer conn.Close()
	fmt.Println("Accepted connection from", conn.RemoteAddr())
	// 在这里处理客户端连接的逻辑
}

// 启动客户端
func startClient() {
	fmt.Println("Starting client...")

	// 让操作系统自动选择一个空闲的端口
	conn, err := net.Dial("tcp", "localhost:0")
	if err != nil {
		fmt.Println("Error starting client:", err)
		return
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	fmt.Println("Client started on port:", localAddr.Port)
	// 在这里实现客户端逻辑
}
