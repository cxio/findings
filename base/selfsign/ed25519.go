package selfsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"log"
)

// 创建自签名证书
// 用于 TLS/SSL 连接以获得它的好处，P2P网络中的客户端会忽略证书的验证。
// 签名算法：ed25519
func GenerateSelfSigned25519() (tls.Certificate, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalln("[Error] generate private key:", err)
	}
	return WithDNS(privateKey, "findings", "Blockchain::cxio.Findings")
}
