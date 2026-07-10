package feed

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
)

// maxZipMemberBytes caps how much of a single archive member is read, as a
// guard against decompression bombs.
const maxZipMemberBytes = 4 << 20

// ExtractZipMembers returns the contents of archive members whose base name
// starts with prefix and ends with suffix. Only matched members are
// decompressed, so filtering a large archive stays cheap.
func ExtractZipMembers(zipData []byte, prefix, suffix string) ([][]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("open feed archive: %w", err)
	}
	var members [][]byte
	for _, f := range r.File {
		name := path.Base(f.Name)
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		data, err := readZipMember(f)
		if err != nil {
			return nil, err
		}
		members = append(members, data)
	}
	return members, nil
}

func readZipMember(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open archive member %s: %w", f.Name, err)
	}
	defer func() {
		_ = rc.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(rc, maxZipMemberBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read archive member %s: %w", f.Name, err)
	}
	if len(data) > maxZipMemberBytes {
		return nil, fmt.Errorf("archive member %s exceeds the %d MiB size limit", f.Name, maxZipMemberBytes>>20)
	}
	return data, nil
}
