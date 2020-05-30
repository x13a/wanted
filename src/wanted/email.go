package wanted

import (
	"bytes"
	"compress/gzip"
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
)

const (
	emailNewLine    = "\r\n"
	emailMaxLineLen = 76
)

type emailMessage struct {
	From        mail.Address
	To          []mail.Address
	Subject     string
	Body        string
	Attachments []emailAttachment
}

type emailAttachment struct {
	Header textproto.MIMEHeader
	Buffer []byte
}

func (m *emailMessage) SetFrom(name, addr string) {
	m.From = mail.Address{name, addr}
}

func (m *emailMessage) AddTo(name, addr string) {
	m.To = append(m.To, mail.Address{name, addr})
}

func (m *emailMessage) MakeHeader(boundary string) textproto.MIMEHeader {
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

func (m *emailMessage) AddAttachment(path string, compress bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	finfo, err := f.Stat()
	if err != nil {
		return err
	}
	// Downcast
	buf := bytes.NewBuffer(make(
		[]byte,
		0,
		base64.StdEncoding.EncodedLen(int(finfo.Size())),
	))
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	if compress {
		zw := gzip.NewWriter(encoder)
		if _, err = io.Copy(zw, f); err != nil {
			return err
		}
		if err = zw.Close(); err != nil {
			return err
		}
	} else {
		if _, err = io.Copy(encoder, f); err != nil {
			return err
		}
	}
	encoder.Close()
	h := make(textproto.MIMEHeader, 3)
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Transfer-Encoding", "base64")
	h.Set(
		"Content-Disposition",
		"attachment; filename=\""+filepath.Base(f.Name())+"\"",
	)
	m.Attachments = append(m.Attachments, emailAttachment{h, buf.Bytes()})
	return nil
}

type emailWriter struct {
	w io.Writer
	n int64
}

func (w *emailWriter) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(p)
	w.n += int64(n)
	return
}

func (m *emailMessage) WriteTo(w io.Writer) (n int64, err error) {
	ww := &emailWriter{w: w}
	defer func() {
		n = ww.n
	}()
	writer := multipart.NewWriter(ww)
	for k, v := range m.MakeHeader(writer.Boundary()) {
		for _, val := range v {
			if _, err = io.WriteString(
				ww,
				k+": "+val+emailNewLine,
			); err != nil {
				return
			}
		}
	}
	if _, err = io.WriteString(ww, emailNewLine); err != nil {
		return
	}
	h := make(textproto.MIMEHeader, 1)
	h.Set("Content-Type", "text/plain; charset=\"us-ascii\"")
	var part io.Writer
	part, err = writer.CreatePart(h)
	if err != nil {
		return
	}
	if _, err = io.WriteString(part, m.Body); err != nil {
		return
	}
	if _, err = io.WriteString(part, emailNewLine); err != nil {
		return
	}
	for _, attachment := range m.Attachments {
		part, err = writer.CreatePart(attachment.Header)
		if err != nil {
			return
		}
		bufLen := len(attachment.Buffer)
		i := 0
		for i < bufLen {
			pos := min(i+emailMaxLineLen, bufLen)
			if _, err = part.Write(attachment.Buffer[i:pos]); err != nil {
				return
			}
			if _, err = io.WriteString(part, emailNewLine); err != nil {
				return
			}
			i = pos
		}
	}
	if err = writer.Close(); err != nil {
		return
	}
	_, err = io.WriteString(ww, emailNewLine)
	return
}

func sendMailTLS(
	addr string,
	auth smtp.Auth,
	msg *emailMessage,
	timeout time.Duration,
	deadline time.Time,
) error {
	hostname := getHostnameFromHost(addr)
	if hostname == addr {
		addr += ":465"
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout, Deadline: deadline},
		"tcp",
		addr,
		&tls.Config{ServerName: hostname},
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, hostname)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.Auth(auth); err != nil {
		return err
	}
	if err = c.Mail(msg.From.Address); err != nil {
		return err
	}
	for _, rcpt := range msg.To {
		if err = c.Rcpt(rcpt.Address); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err = msg.WriteTo(w); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
