package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func encodeJSON(value interface{}) ([]byte, error) {
	var buf bytes.Buffer

	e := json.NewEncoder(&buf)
	e.SetIndent("", "  ")

	if err := e.Encode(value); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func writeFile(filePath string, data []byte, mode os.FileMode) error {
	dirPath := filepath.Dir(filePath)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("cannot create directory %q: %w",
			dirPath, err)
	}

	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		mode)
	if os.IsExist(err) {
		return fmt.Errorf("%q already exists", filePath)
	} else if err != nil {
		return fmt.Errorf("cannot open %q: %w", filePath, err)
	}

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("cannot write %q: %w", filePath, err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("cannot sync %q: %w", filePath, err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("cannot close %q: %w", filePath, err)
	}

	return nil
}
