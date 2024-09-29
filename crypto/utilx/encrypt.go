package utilx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Encrypt 使用 256 位 AES-GCM 加密数据。
// 该加密算法既对数据实施了加密，同时也提供了数据完整性检查。
// 注意 nonce 前置在了密文头部。
// 参考：github.com/gtank/cryptopasta
// @text 待加密的明文数据
// @key 一个32字节长密钥的指针
// @return 密文（含前置nonce）
func Encrypt(text []byte, key *[32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, text, nil), nil
}

// Decrypt 使用 256 位 AES-GCM 解密数据。
// 该加密算法既对数据实施了加密，同时也提供了数据完整性检查。
// 参考：github.com/gtank/cryptopasta
// @data 已加密数据的密文
// @key 一个32字节长密钥的指针
// @return 已解密的明文
func Decrypt(data []byte, key *[32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nsize := gcm.NonceSize()

	if len(data) < nsize {
		return nil, errors.New("ciphered text too short")
	}
	// 密文头部为 nonce
	nonce, data := data[:nsize], data[nsize:]

	return gcm.Open(nil, nonce, data, nil)
}
