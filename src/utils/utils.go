package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func Encrypt(password string, data []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func Decrypt(password string, data []byte) ([]byte, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

func Srm(path string, force bool) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer func() {
		if err1 := file.Close(); err == nil {
			err = err1
		}
		if err == nil || force {
			path1 := filepath.Join(filepath.Dir(path), "stdio.h")
			err1 := os.Rename(path, path1)
			if err == nil {
				err = err1
			}
			if err1 != nil {
				path1 = path
			}
			if err1 = os.Remove(path1); err == nil {
				err = err1
			}
		}
	}()
	fileInfo, err := file.Stat()
	if err != nil {
		return
	}
	fileSize := fileInfo.Size()
	chunkSize := 1 << 21
	chunkSize64 := int64(chunkSize)
	if chunkSize64 > fileSize {
		chunkSize64 = fileSize
		chunkSize = int(fileSize)
	}
	buf := make([]byte, chunkSize)
	parts := fileSize / chunkSize64
	doLastPart := true
	for i := int64(0); i < parts; i++ {
		if _, err = file.Write(buf); err != nil {
			doLastPart = false
			break
		}
	}
	if doLastPart {
		if rem := fileSize % chunkSize64; rem != 0 {
			_, err = file.Write(buf[:rem])
		}
	}
	if err1 := file.Sync(); err == nil {
		err = err1
	}
	return
}

func AddrToBroadcastIP(addr net.Addr) net.IP {
	ipNet, ok := addr.(*net.IPNet)
	if !ok {
		return nil
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil
	}
	ip := net.IP(make([]byte, len(ip4)))
	for idx, b := range ip4 {
		ip[idx] = b | ^ipNet.Mask[idx]
	}
	return ip
}

func IsErrNetClosing(err error) bool {
	// https://github.com/golang/go/issues/4373
	// https://golang.org/src/internal/poll/fd.go?h=ErrNetClosing
	return strings.HasSuffix(err.Error(), "use of closed network connection")
}

func Min(v ...int) int {
	res := v[0]
	for _, i := range v[1:] {
		if i < res {
			res = i
		}
	}
	return res
}

func Max(v ...int) int {
	res := v[0]
	for _, i := range v[1:] {
		if i > res {
			res = i
		}
	}
	return res
}

func HostToHostname(s string) string {
	pos := strings.LastIndex(s, ":")
	if pos == -1 {
		return s
	}
	return s[:pos]
}

func HostnameToDomain(s string) string {
	parts := strings.Split(s, ".")
	return strings.Join(parts[Max(0, len(parts)-2):], ".")
}
