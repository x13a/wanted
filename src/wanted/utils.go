package wanted

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func max(v ...int) int {
	res := v[0]
	for _, i := range v[1:] {
		if i > res {
			res = i
		}
	}
	return res
}

func min(v ...int) int {
	res := v[0]
	for _, i := range v[1:] {
		if i < res {
			res = i
		}
	}
	return res
}

func postFiles(
	client *http.Client,
	url string,
	files []string,
	errors chan<- error,
	ignoreFileNotFound bool,
	compress bool,
) {
	if client == nil {
		client = &http.Client{}
	}
	r, w := io.Pipe()
	defer r.Close()
	mw := multipart.NewWriter(w)
	errchan := make(chan error, 1)
	go func() {
		defer w.Close()
		upload := func(index int, path string) error {
			file, err := os.Open(path)
			if err != nil {
				if ignoreFileNotFound {
					errors <- err
					return nil
				}
				return err
			}
			defer file.Close()
			part, err := mw.CreateFormFile(
				"file"+strconv.Itoa(index),
				filepath.Base(file.Name()),
			)
			if err != nil {
				return err
			}
			if compress {
				compressor := gzip.NewWriter(part)
				if _, err = io.Copy(compressor, file); err != nil {
					return err
				}
				return compressor.Close()
			}
			_, err = io.Copy(part, file)
			return err
		}
		for idx, path := range files {
			if err := upload(idx, path); err != nil {
				errchan <- err
				return
			}
		}
		errchan <- mw.Close()
	}()
	if resp, err := client.Post(url, mw.FormDataContentType(), r); err != nil {
		errors <- err
	} else {
		resp.Body.Close()
		if err = <-errchan; err != nil {
			errors <- err
		}
	}
}

func getHostnameFromHost(s string) string {
	pos := strings.LastIndex(s, ":")
	if pos == -1 {
		return s
	}
	return s[:pos]
}

func getDomainFromHostname(s string) string {
	sep := "."
	parts := strings.Split(s, sep)
	return strings.Join(parts[max(0, len(parts)-2):], sep)
}

func encryptAESGCM(password string, data []byte) ([]byte, error) {
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

func decryptAESGCM(password string, data []byte) ([]byte, error) {
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

func sendBroadcast(
	address string,
	data []byte,
	errors chan<- error,
	deadline time.Time,
) {
	network := "udp4"
	srcaddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		errors <- err
		return
	}
	conn, err := net.ListenUDP(network, srcaddr)
	if err != nil {
		errors <- err
		return
	}
	defer conn.Close()
	if err = conn.SetDeadline(deadline); err != nil {
		errors <- err
		return
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		errors <- err
		return
	}
	suffix := ":" + strconv.Itoa(srcaddr.Port)
	for _, iface := range interfaces {
		flags := net.FlagUp | net.FlagBroadcast
		if iface.Flags&flags != flags {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			errors <- err
			continue
		}
		for _, addr := range addrs {
			broadcast := addrToBroadcast(addr)
			if broadcast == nil {
				continue
			}
			dest, err := net.ResolveUDPAddr(
				network,
				broadcast.String()+suffix,
			)
			if err != nil {
				errors <- err
				continue
			}
			if _, err = conn.WriteToUDP(data, dest); err != nil {
				errors <- err
				if os.IsTimeout(err) {
					return
				}
			}
		}
	}
}

func addrToBroadcast(addr net.Addr) net.IP {
	ipnet, ok := addr.(*net.IPNet)
	if !ok {
		return nil
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil
	}
	broadcast := net.IP(make([]byte, len(ip4)))
	mask := ipnet.Mask
	for idx, b := range ip4 {
		broadcast[idx] = b | ^mask[idx]
	}
	return broadcast
}
