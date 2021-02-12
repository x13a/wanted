package email

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/x13a/wanted/utils"
)

const (
	newLine    = "\r\n"
	maxLineLen = 76
)

type Message struct {
	From        mail.Address
	To          []mail.Address
	Subject     string
	Body        string
	Attachments []Attachment
}

type Attachment struct {
	Header textproto.MIMEHeader
	Buffer []byte
}

func (m *Message) SetFrom(name, addr string) {
	m.From = mail.Address{name, addr}
}

func (m *Message) AddTo(name, addr string) {
	m.To = append(m.To, mail.Address{name, addr})
}

func (m *Message) makeHeader(boundary string) textproto.MIMEHeader {
	h := make(textproto.MIMEHeader, 6)
	h.Set("Date", time.Now().Format(time.RFC1123Z))
	h.Set("From", m.From.String())
	to := make([]string, len(m.To))
	for idx, addr := range m.To {
		to[idx] = addr.String()
	}
	h.Set("To", strings.Join(to, ", "))
	h.Set("Subject", m.Subject)
	h.Set("MIME-Version", "1.0")
	h.Set("Content-Type", "multipart/mixed; boundary=\""+boundary+"\"")
	return h
}

func (m *Message) AddAttachment(path string, compress bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	// Downcast
	buf := bytes.NewBuffer(make(
		[]byte,
		0,
		base64.StdEncoding.EncodedLen(int(fileInfo.Size())),
	))
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	if compress {
		compressor := gzip.NewWriter(encoder)
		if _, err = io.Copy(compressor, file); err != nil {
			return err
		}
		if err = compressor.Close(); err != nil {
			return err
		}
	} else {
		if _, err = io.Copy(encoder, file); err != nil {
			return err
		}
	}
	if err = encoder.Close(); err != nil {
		return err
	}
	h := make(textproto.MIMEHeader, 3)
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Transfer-Encoding", "base64")
	h.Set(
		"Content-Disposition",
		"attachment; filename=\""+filepath.Base(file.Name())+"\"",
	)
	m.Attachments = append(m.Attachments, Attachment{h, buf.Bytes()})
	return nil
}

type writer struct {
	w io.Writer
	n int64
}

func (w *writer) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(p)
	w.n += int64(n)
	return
}

func (m *Message) WriteTo(w io.Writer) (n int64, err error) {
	ew := &writer{w: w}
	defer func() { n = ew.n }()
	mw := multipart.NewWriter(ew)
	for key, values := range m.makeHeader(mw.Boundary()) {
		for _, value := range values {
			if _, err = io.WriteString(
				ew,
				key+": "+value+newLine,
			); err != nil {
				return
			}
		}
	}
	if _, err = io.WriteString(ew, newLine); err != nil {
		return
	}
	h := make(textproto.MIMEHeader, 1)
	h.Set("Content-Type", "text/plain; charset=\"us-ascii\"")
	part, err := mw.CreatePart(h)
	if err != nil {
		return
	}
	if _, err = io.WriteString(part, m.Body); err != nil {
		return
	}
	if _, err = io.WriteString(part, newLine); err != nil {
		return
	}
	for _, attachment := range m.Attachments {
		part, err = mw.CreatePart(attachment.Header)
		if err != nil {
			return
		}
		bufLen := len(attachment.Buffer)
		for i, pos := 0, 0; i < bufLen; i = pos {
			pos = utils.Min(i+maxLineLen, bufLen)
			if _, err = part.Write(attachment.Buffer[i:pos]); err != nil {
				return
			}
			if _, err = io.WriteString(part, newLine); err != nil {
				return
			}
		}
	}
	if err = mw.Close(); err != nil {
		return
	}
	_, err = io.WriteString(ew, newLine)
	return
}

func SendMailTLS(
	ctx context.Context,
	addr string,
	auth smtp.Auth,
	msg Message,
) error {
	hostname := utils.HostToHostname(addr)
	if hostname == addr {
		addr += ":465"
	}
	conn, err := (&tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    &tls.Config{ServerName: hostname},
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopChan := make(chan struct{})
	defer close(stopChan)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stopChan:
		}
	}()
	client, err := smtp.NewClient(conn, hostname)
	if err != nil {
		return err
	}
	defer client.Close()
	if err = client.Auth(auth); err != nil {
		return err
	}
	if err = client.Mail(msg.From.Address); err != nil {
		return err
	}
	for _, rcpt := range msg.To {
		if err = client.Rcpt(rcpt.Address); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err = msg.WriteTo(w); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
