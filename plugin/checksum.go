package plugin

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

type Checksummer struct {
	checksums map[string][]byte
}

func NewChecksummer(f io.Reader) (*Checksummer, error) {
	scanner := bufio.NewScanner(f)

	var line int
	checksummer := &Checksummer{checksums: map[string][]byte{}}
	for scanner.Scan() {
		line++
		fields := strings.Fields(scanner.Text())
		// checksums file should have "hash" and "filename" fields
		if len(fields) != 2 {
			return nil, fmt.Errorf("record on line %d: wrong number of fields: expected=2, actual=%d", line, len(fields))
		}
		hash := fields[0]
		filename := fields[1]

		checksum, err := hex.DecodeString(hash)
		if err != nil {
			return nil, err
		}
		checksummer.checksums[filename] = checksum
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return checksummer, nil
}

func (c *Checksummer) Verify(filename string, f io.Reader) error {
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return err
	}

	expected := c.checksums[filename]
	actual := hash.Sum(nil)
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("Failed to match checksums: expected=%x, actual=%x", expected, actual)
	}

	return nil
}
