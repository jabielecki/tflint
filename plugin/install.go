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

	tmpfile, err := ioutil.TempFile("", "tflint-ruleset-*.zip")
	if err != nil {
		return "", fmt.Errorf("Failed to create a temp file: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	for _, asset := range release.Assets {
		log.Printf("[DEBUG] asset found: %s", asset.GetName())

		if asset.GetName() != config.AssetName() {
			continue
		}

		// Download zip file to temp file from GitHub
		log.Printf("[DEBUG] Request to https://api.github.com/repos/%s/%s/releases/assets/%d", config.SourceOwner, config.SourceRepo, asset.GetID())
		remoteReader, _, err := client.Repositories.DownloadReleaseAsset(ctx, config.SourceOwner, config.SourceRepo, asset.GetID(), http.DefaultClient)
		if err != nil {
			return "", fmt.Errorf("Failed to download GitHub release asset: %s", err)
		}

		_, err = io.Copy(tmpfile, remoteReader)
		remoteReader.Close()
		if err != nil {
			return "", fmt.Errorf("Failed to copy to temp file from remote file: %s", err)
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
			return "", fmt.Errorf("Could not found `%s` file in %s", filepath.Base(path), asset.GetName())
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
		break
	}

	return path, nil
}
