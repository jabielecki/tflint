package plugin

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/go-github/v35/github"
	"github.com/terraform-linters/tflint/tflint"
)

func Install(config *tflint.PluginConfig) (string, error) {
	dir, err := getPluginDir()
	if err != nil {
		return "", fmt.Errorf("Failed to get plugin dir: %s", err)
	}

	// Mkdir plugin dir
	path := filepath.Join(dir, config.InstallPath())
	log.Printf("[DEBUG] Mkdir plugin dir: %s", filepath.Dir(path))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", fmt.Errorf("Failed to mkdir to %s: %s", filepath.Dir(path), err)
	}

	client := github.NewClient(nil)
	ctx := context.Background()

	// Get release from GitHub
	log.Printf("[DEBUG] Request to https://api.github.com/repos/%s/%s/releases/tags/%s", config.SourceOwner, config.SourceRepo, config.TagName())
	release, _, err := client.Repositories.GetReleaseByTag(ctx, config.SourceOwner, config.SourceRepo, config.TagName())
	if err != nil {
		return "", fmt.Errorf("Failed to get GitHub release by tag: %s", err)
	}
	assets := map[string]*github.ReleaseAsset{}
	for _, asset := range release.Assets {
		log.Printf("[DEBUG] asset found: %s", asset.GetName())
		assets[asset.GetName()] = asset
	}

	// Download checksums.txt
	checksumAsset, exists := assets["checksums.txt"]
	if !exists {
		return "", fmt.Errorf("checksums.txt not found in the GitHub release")
	}
	log.Printf("[DEBUG] Request to https://api.github.com/repos/%s/%s/releases/assets/%d", config.SourceOwner, config.SourceRepo, checksumAsset.GetID())
	checksumReader, _, err := client.Repositories.DownloadReleaseAsset(ctx, config.SourceOwner, config.SourceRepo, checksumAsset.GetID(), http.DefaultClient)
	if err != nil {
		return "", fmt.Errorf("Failed to download GitHub release checksums asset: %s", err)
	}

	// Download zip file to temp file from GitHub
	tmpfile, err := ioutil.TempFile("", "tflint-ruleset-*.zip")
	if err != nil {
		return "", fmt.Errorf("Failed to create a temp file: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	zipAsset, exists := assets[config.AssetName()]
	if !exists {
		return "", fmt.Errorf("%s not found in the GitHub release", config.AssetName())
	}
	log.Printf("[DEBUG] Request to https://api.github.com/repos/%s/%s/releases/assets/%d", config.SourceOwner, config.SourceRepo, zipAsset.GetID())
	remoteReader, _, err := client.Repositories.DownloadReleaseAsset(ctx, config.SourceOwner, config.SourceRepo, zipAsset.GetID(), http.DefaultClient)
	if err != nil {
		return "", fmt.Errorf("Failed to download GitHub release asset: %s", err)
	}
	_, err = io.Copy(tmpfile, remoteReader)
	remoteReader.Close()
	if err != nil {
		return "", fmt.Errorf("Failed to copy to temp file from remote file: %s", err)
	}

	// Verify checksums of the downloaded zip file
	if _, err := tmpfile.Seek(0, 0); err != nil {
		return "", fmt.Errorf("Failed to seek for checksumming: %s", err)
	}
	checksummer, err := NewChecksummer(checksumReader)
	if err != nil {
		return "", fmt.Errorf("Failed to parse checksums file: %s", err)
	}
	if err = checksummer.Verify(zipAsset.GetName(), tmpfile); err != nil {
		return "", fmt.Errorf("Failed to verify checksums: %s", err)
	}

	// Restore binary from temp zip file
	tmpfileStat, err := tmpfile.Stat()
	if err != nil {
		return "", fmt.Errorf("Failed to get stat of temp file: %s", err)
	}
	zipReader, err := zip.NewReader(tmpfile, tmpfileStat.Size())
	if err != nil {
		return "", fmt.Errorf("Failed to create a zip reader from temp file: %s", err)
	}

	var binaryReader io.ReadCloser
	for _, f := range zipReader.File {
		log.Printf("[DEBUG] file found in zip: %s", f.Name)
		if f.Name != filepath.Base(path) {
			continue
		}

		binaryReader, err = f.Open()
		if err != nil {
			return "", fmt.Errorf("Failed to open `%s` file from zip: %s", f.Name, err)
		}
		break
	}
	if binaryReader == nil {
		return "", fmt.Errorf("Could not found `%s` file in %s", filepath.Base(path), zipAsset.GetName())
	}

	outputFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("Failed to create binary file: %s", err)
	}
	defer outputFile.Close()

	if _, err := io.Copy(outputFile, binaryReader); err != nil {
		return "", fmt.Errorf("Failed to copy binary file: %s", err)
	}

	log.Printf("[DEBUG] Create %s successfully", path)

	return path, nil
}
