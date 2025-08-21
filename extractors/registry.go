package extractors

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var regfHeader = []byte("regf")
var hbinHeader = []byte("hbin")


func asciiToUTF16LE(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		b = append(b, s[i], 0x00)
	}
	return b
}

func containsAny(h []byte, need [][]byte) bool {
	for _, n := range need {
		if len(n) > 0 && bytes.Contains(h, n) {
			return true
		}
	}
	return false
}

func readAtExact(r io.ReaderAt, off int64, buf []byte) error {
	n, err := r.ReadAt(buf, off)
	if err != nil && err != io.EOF {
		return err
	}
	if n != len(buf) {
		return io.ErrUnexpectedEOF
	}
	return nil
}


func classifyHive(chunk []byte) string {
	u := asciiToUTF16LE
	switch {
	case containsAny(chunk, [][]byte{u(`\SAM\Domains`), u(`\SAM\`), []byte(`\SAM\`), u(`\SAM`), []byte("SAM")}):
		return "SAM"
	case containsAny(chunk, [][]byte{u(`\SECURITY\Policy`), u(`\Policy\Secrets`), u(`NL$KM`), []byte(`\SECURITY\`), []byte("SECURITY")}):
		return "SECURITY"
	case containsAny(chunk, [][]byte{u(`\ControlSet`), u(`\Select`), u(`\SYSTEM\`), []byte(`\ControlSet`), []byte("SYSTEM")}):
		return "SYSTEM"
	case containsAny(chunk, [][]byte{u(`\SOFTWARE\Microsoft`), []byte(`\SOFTWARE\Microsoft`)}):
		return "SOFTWARE"
	case containsAny(chunk, [][]byte{u(`\DEFAULT\`), []byte(`\DEFAULT\`)}):
		return "DEFAULT"
	case containsAny(chunk, [][]byte{u(`\COMPONENTS`), []byte(`\COMPONENTS`)}):
		return "COMPONENTS"
	default:
		return ""
	}
}

func writeHive(outDir, label string, off int64, chunk []byte) (string, error) {
	if label == "" {
		label = "hive"
	}
	out := filepath.Join(outDir, fmt.Sprintf("%s_0x%X.regf", label, off))
	return out, os.WriteFile(out, chunk, 0644)
}

func parseHBIN(h []byte) (relOffset int64, size int, err error) {
	if len(h) < 0x20 || !bytes.Equal(h[:4], hbinHeader) {
		return 0, 0, errors.New("not hbin")
	}
	rel := int64(int32(binary.LittleEndian.Uint32(h[0x04:0x08])))
	sz := int(int32(binary.LittleEndian.Uint32(h[0x08:0x0C])))
	if sz <= 0 || sz%0x1000 != 0 || sz > (256<<20) {
		return 0, 0, fmt.Errorf("invalid hbin size %d", sz)
	}
	return rel, sz, nil
}

func findNext(r io.ReaderAt, start int64, pattern []byte, window, overlap int) (int64, error) {
	if window < 8<<20 {
		window = 8 << 20
	}
	if overlap < 0x4000 {
		overlap = 0x4000
	}
	buf := make([]byte, window)
	off := start
	for {
		n, err := r.ReadAt(buf, off)
		if n == 0 && err != nil {
			return 0, err
		}
		chunk := buf[:n]
		if idx := bytes.Index(chunk, pattern); idx >= 0 {
			return off + int64(idx), nil
		}
		if err == io.EOF {
			return 0, io.EOF
		}
		if n < window {
			return 0, io.EOF
		}
		off += int64(n - overlap)
	}
}

func findHBINWithRelOffset(r io.ReaderAt, forwardFrom int64, expectRel int64, filesize int64) (pos int64, size int, err error) {
	if p, e := findNext(r, forwardFrom, hbinHeader, 8<<20, 0x4000); e == nil {
		hdr := make([]byte, 0x40)
		if err := readAtExact(r, p, hdr); err == nil {
			if rel, sz, e2 := parseHBIN(hdr); e2 == nil && rel == expectRel {
				return p, sz, nil
			}
		}
		cur := p + 4
		for {
			pp, e2 := findNext(r, cur, hbinHeader, 8<<20, 0x4000)
			if e2 != nil {
				break
			}
			if err := readAtExact(r, pp, hdr); err == nil {
				if rel, sz, e3 := parseHBIN(hdr); e3 == nil && rel == expectRel {
					return pp, sz, nil
				}
			}
			cur = pp + 4
		}
	}

	cur := int64(0)
	hdr := make([]byte, 0x40)
	for {
		pp, e := findNext(r, cur, hbinHeader, 16<<20, 0x8000)
		if e != nil {
			return 0, 0, e
		}
		if pp >= filesize {
			return 0, 0, io.EOF
		}
		if err := readAtExact(r, pp, hdr); err == nil {
			if rel, sz, e2 := parseHBIN(hdr); e2 == nil && rel == expectRel {
				return pp, sz, nil
			}
		}
		cur = pp + 4
	}
}

func stitchHive(r io.ReaderAt, start int64, filesize int64) ([]byte, error) {
	hdr := make([]byte, 0x1000)
	if err := readAtExact(r, start, hdr); err != nil {
		return nil, fmt.Errorf("read regf header: %w", err)
	}
	if !bytes.Equal(hdr[:4], regfHeader) {
		return nil, errors.New("not regf")
	}
	binsSize := int(binary.LittleEndian.Uint32(hdr[0x28:0x2C]))
	if binsSize <= 0 || binsSize%0x1000 != 0 || binsSize > (1<<30) {
		return nil, fmt.Errorf("invalid bins size %d", binsSize)
	}

	out := make([]byte, 0, 0x1000+binsSize)
	out = append(out, hdr...)

	want := binsSize
	expectRel := int64(0)
	searchFrom := start + 0x1000

	for want > 0 {
		p, sz, err := findHBINWithRelOffset(r, searchFrom, expectRel, filesize)
		if err != nil {
			return nil, fmt.Errorf("find hbin(rel=%d): %w", expectRel, err)
		}
		if sz > want {
			sz = want
		}
		bin := make([]byte, sz)
		if err := readAtExact(r, p, bin); err != nil {
			return nil, fmt.Errorf("read hbin: %w", err)
		}
		out = append(out, bin...)
		want -= sz
		expectRel += int64(sz)
		searchFrom = p + int64(sz)
	}
	return out, nil
}

func CarveRegistryHives(data []byte, outDir string) ([]string, error) {
	var carved []string
	offset := 0
	seen := map[int]struct{}{}

	for {
		i := bytes.Index(data[offset:], regfHeader)
		if i == -1 {
			break
		}
		offset += i
		if _, dup := seen[offset]; dup {
			offset += 4
			continue
		}
		if offset+0x2C > len(data) {
			offset += 4
			continue
		}

		ok := false
		bins := int(binary.LittleEndian.Uint32(data[offset+0x28 : offset+0x2C]))
		total := 0x1000 + bins
		if bins > 0 && bins%0x1000 == 0 && total > 0 && offset+total <= len(data) {
			if offset+0x1000+4 <= len(data) && bytes.Equal(data[offset+0x1000:offset+0x1004], hbinHeader) {
				hive := data[offset : offset+total]
				if p, err := writeHive(outDir, classifyHive(hive), int64(offset), hive); err == nil {
					carved = append(carved, p)
					seen[offset] = struct{}{}
					ok = true
				}
			}
		}
		if !ok {
			r := bytes.NewReader(data)
			if hive, err := stitchHive(r, int64(offset), int64(len(data))); err == nil && len(hive) >= 0x1000 {
				if p, werr := writeHive(outDir, classifyHive(hive), int64(offset), hive); werr == nil {
					carved = append(carved, p)
					seen[offset] = struct{}{}
				}
			}
		}
		offset += 4
	}
	return carved, nil
}

func CarveRegistryHivesStream(path string, outDir string, window, overlap int) ([]string, error) {
	if window < 64<<20 {
		window = 64 << 20
	}
	if overlap < 0x3000 {
		overlap = 0x3000
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	filesize := stat.Size()

	var carved []string
	seen := map[int64]struct{}{}

	buf := make([]byte, window)
	var pos int64 = 0

	for {
		n, err := f.ReadAt(buf, pos)
		if n == 0 && err != nil {
			if err == io.EOF {
				break
			}
			return carved, err
		}
		chunk := buf[:n]

		off := 0
		for {
			i := bytes.Index(chunk[off:], regfHeader)
			if i == -1 {
				break
			}
			global := pos + int64(off+i)
			if _, dup := seen[global]; dup {
				off += i + 4
				continue
			}

			if hive, herr := stitchHive(f, global, filesize); herr == nil && len(hive) >= 0x1000 {
				if pathOut, werr := writeHive(outDir, classifyHive(hive), global, hive); werr == nil {
					carved = append(carved, pathOut)
					seen[global] = struct{}{}
				}
			}
			off += i + 4
		}

		if err == io.EOF || n < window {
			break
		}
		pos += int64(n - overlap)
	}
	return carved, nil
}
