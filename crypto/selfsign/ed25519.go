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
		log.Fatal("Failed to generate private key: ", err)
	}
	return WithDNS(privateKey, "findings", "Blockchain::cxio.Findings")

	/*
		// 生成随机序列号
		serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return tls.Certificate{}, err
		}
		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"Blockchain::cxio.Findings"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0), // 有效期为1年
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
		if err != nil {
			return tls.Certificate{}, err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		// 需先转换到DER格式
		keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			log.Fatalf("Error convert private key to DER format: %v", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

		return tls.X509KeyPair(certPEM, keyPEM)
	*/
}
