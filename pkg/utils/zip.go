package utils

import (
	"archive/zip"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// GenerateRandomFileName generates a random file name with the given extension
func GenerateRandomFileName(extension string) (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x%s", b, extension), nil
}

// ZipDirectory zips the specified directory into a file with a random name
func ZipDirectory(source string) (string, error) {
	// Generate a random zip file name
	var zipFilePath string
	for {
		randomFileName, err := GenerateRandomFileName(".zip")
		if err != nil {
			return "", err
		}
		zipFilePath = filepath.Join(os.TempDir(), randomFileName)
		// Check if the file already exists
		_, err = os.Stat(zipFilePath)
		if os.IsNotExist(err) {
			// File does not exist, we can use this name
			break
		}
		// If file exists, generate a new name
	}

	zipFile, err := os.Create(zipFilePath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create a relative path
		relPath, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}

		// Replace backslashes with forward slashes for cross-platform compatibility
		relPath = filepath.ToSlash(relPath)

		if info.IsDir() {
			// Skip adding directories explicitly
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	return zipFilePath, nil
}
