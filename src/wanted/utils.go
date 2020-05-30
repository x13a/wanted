package wanted

import (
	"compress/gzip"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	r, w := io.Pipe()
	defer r.Close()
	m := multipart.NewWriter(w)
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
			part, err := m.CreateFormFile(
				"file"+strconv.Itoa(index),
				filepath.Base(file.Name()),
			)
			if err != nil {
				return err
			}
			if compress {
				zw := gzip.NewWriter(part)
				if _, err = io.Copy(zw, file); err != nil {
					return err
				}
				return zw.Close()
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
		errchan <- m.Close()
	}()
	if resp, err := client.Post(url, m.FormDataContentType(), r); err != nil {
		errors <- err
	} else {
		resp.Body.Close()
		errors <- (<-errchan)
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
