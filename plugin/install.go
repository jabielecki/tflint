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
	"runtime"
	"strings"

	"github.com/google/go-github/v35/github"
	"github.com/terraform-linters/tflint/tflint"
	"golang.org/x/crypto/openpgp"
)

// InstallConfig is a config for plugin installation.
// This is a wrapper for PluginConfig and manages naming conventions
// and directory names for installation.
type InstallConfig struct {
	*tflint.PluginConfig
}

// NewInstallConfig returns a new InstallConfig from passed PluginConfig.
func NewInstallConfig(config *tflint.PluginConfig) *InstallConfig {
	return &InstallConfig{PluginConfig: config}
}

// ManuallyInstalled returns whether the plugin should be installed manually.
// If source or version is omitted, you will have to install it manually.
func (c *InstallConfig) ManuallyInstalled() bool {
	return c.Version == "" || c.Source == ""
}

// InstallPath returns an installation path from the plugin directory.
func (c *InstallConfig) InstallPath() string {
	return filepath.Join(c.Source, c.Version, fmt.Sprintf("tflint-ruleset-%s", c.Name))
}

// TagName returns a tag name that the GitHub release should meet.
// The version must not contain leading "v", as the prefix "v" is added here,
// and the release tag must be in a format similar to `v1.1.1`.
func (c *InstallConfig) TagName() string {
	return fmt.Sprintf("v%s", c.Version)
}

// AssetName returns a name that the asset contained in the release should meet.
// The name must be in a format similar to `tflint-ruleset-aws_darwin_amd64.zip`.
func (c *InstallConfig) AssetName() string {
	return fmt.Sprintf("tflint-ruleset-%s_%s_%s.zip", c.Name, runtime.GOOS, runtime.GOARCH)
}

// GetKeyring returns an ASCII armored signing key.
// If the plugin is under the terraform-linters organization, you can use the built-in key even if the keyring is omitted.
func (c *InstallConfig) GetKeyring() string {
	if c.Keyring != "" {
		return c.Keyring
	}
	if c.SourceOwner == "terraform-linters" {
		return builtinKeyring
	}
	return c.Keyring
}

// Install fetches the release from GitHub and puts the binary in the plugin directory.
// The installation process checks the checksum of the downloaded zip file and signature of the checksum file to prevent supply chain attacks.
// Therefore, the release must always contain the checksum file and its signature file.
// In addition, this installation process has the following conventions:
//
//   - The release must be tagged with a name like v1.1.1
//   - The release must contain an asset with a name like tflint-ruleset-{name}_{GOOS}_{GOARCH}.zip
//   - The zip file must contain a binary named tflint-ruleset-{name} (TODO: .exe is needed in Windows?)
//   - The release must contain a checksum file for the zip file with the name checksums.txt
//   - The checksum file must contain a sha256 hash and filename
//   - The release must contain a signature file for the checksum file with the name checksums.txt.sig
//   - The signature file must be binary OpenPGP format
//
func (c *InstallConfig) Install() (string, error) {
	dir, err := getPluginDir()
	if err != nil {
		return "", fmt.Errorf("Failed to get plugin dir: %s", err)
	}

	path := filepath.Join(dir, c.InstallPath())
	log.Printf("[DEBUG] Mkdir plugin dir: %s", filepath.Dir(path))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", fmt.Errorf("Failed to mkdir to %s: %s", filepath.Dir(path), err)
	}

	assets, err := c.fetchReleaseAssets()
	if err != nil {
		return "", fmt.Errorf("Failed to fetch GitHub releases: %s", err)
	}

	log.Printf("[DEBUG] Download checksums.txt")
	checksumsFile, err := c.downloadToTempFile(assets["checksums.txt"])
	if checksumsFile != nil {
		defer os.Remove(checksumsFile.Name())
	}
	if err != nil {
		return "", fmt.Errorf("Failed to download checksums.txt: %s", err)
	}

	log.Printf("[DEBUG] Download checksums.txt.sig")
	signatureFile, err := c.downloadToTempFile(assets["checksums.txt.sig"])
	if signatureFile != nil {
		defer os.Remove(signatureFile.Name())
	}
	if err != nil {
		return "", fmt.Errorf("Failed to download checksums.txt.sig: %s", err)
	}

	if err := c.verifySignature(checksumsFile, signatureFile); err != nil {
		return "", fmt.Errorf("Failed to check checksums.txt signature: %s", err)
	}

	log.Printf("[DEBUG] Download %s", c.AssetName())
	zipFile, err := c.downloadToTempFile(assets[c.AssetName()])
	if zipFile != nil {
		defer os.Remove(zipFile.Name())
	}
	if err != nil {
		return "", fmt.Errorf("Failed to download %s: %s", c.AssetName(), err)
	}

	checksummer, err := NewChecksummer(checksumsFile)
	if err != nil {
		return "", fmt.Errorf("Failed to parse checksums file: %s", err)
	}
	if err = checksummer.Verify(c.AssetName(), zipFile); err != nil {
		return "", fmt.Errorf("Failed to verify checksums: %s", err)
	}
	log.Printf("[DEBUG] Matched checksum successfully")

	if err = c.extractFileFromZipFile(zipFile, path); err != nil {
		return "", fmt.Errorf("Failed to extract binary from %s: %s", c.AssetName(), err)
	}

	log.Printf("[DEBUG] Installed %s successfully", path)
	return path, nil
}

func (c *InstallConfig) fetchReleaseAssets() (map[string]*github.ReleaseAsset, error) {
	assets := map[string]*github.ReleaseAsset{}

	client := github.NewClient(nil)
	ctx := context.Background()

	log.Printf("[DEBUG] Request to https://api.github.com/repos/%s/%s/releases/tags/%s", c.SourceOwner, c.SourceRepo, c.TagName())
	release, _, err := client.Repositories.GetReleaseByTag(ctx, c.SourceOwner, c.SourceRepo, c.TagName())
	if err != nil {
		return assets, err
	}

	for _, asset := range release.Assets {
		log.Printf("[DEBUG] asset found: %s", asset.GetName())
		assets[asset.GetName()] = asset
	}
	return assets, nil
}

func (c *InstallConfig) downloadToTempFile(asset *github.ReleaseAsset) (*os.File, error) {
	if asset == nil {
		return nil, fmt.Errorf("file not found in the GitHub release. Does the release contain the file with the correct name ?")
	}

	client := github.NewClient(nil)
	ctx := context.Background()

	log.Printf("[DEBUG] Request to https://api.github.com/repos/%s/%s/releases/assets/%d", c.SourceOwner, c.SourceRepo, asset.GetID())
	downloader, _, err := client.Repositories.DownloadReleaseAsset(ctx, c.SourceOwner, c.SourceRepo, asset.GetID(), http.DefaultClient)
	if err != nil {
		return nil, err
	}

	file, err := ioutil.TempFile("", "tflint-download-temp-file-*")
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(file, downloader); err != nil {
		return file, err
	}
	downloader.Close()
	if _, err := file.Seek(0, 0); err != nil {
		return file, err
	}

	log.Printf("[DEBUG] Downloaded to %s", file.Name())
	return file, nil
}

func (c *InstallConfig) verifySignature(target, signature *os.File) error {
	armoredKeyring := c.GetKeyring()
	if armoredKeyring == "" {
		return fmt.Errorf("No key ring is specified. You must set the plugin developer's keyring in the `keyring` attribute")
	}

	reader := strings.NewReader(armoredKeyring)
	keyring, err := openpgp.ReadArmoredKeyRing(reader)
	if err != nil {
		return err
	}

	_, err = openpgp.CheckDetachedSignature(keyring, target, signature)
	if err != nil {
		return err
	}
	if _, err := target.Seek(0, 0); err != nil {
		return err
	}
	if _, err := signature.Seek(0, 0); err != nil {
		return err
	}

	log.Printf("[DEBUG] Verified signature successfully")
	return nil
}

func (c *InstallConfig) extractFileFromZipFile(zipFile *os.File, savePath string) error {
	zipFileStat, err := zipFile.Stat()
	if err != nil {
		return err
	}
	zipReader, err := zip.NewReader(zipFile, zipFileStat.Size())
	if err != nil {
		return err
	}

	var reader io.ReadCloser
	for _, f := range zipReader.File {
		log.Printf("[DEBUG] file found in zip: %s", f.Name)
		if f.Name != filepath.Base(savePath) {
			continue
		}

		reader, err = f.Open()
		if err != nil {
			return err
		}
		break
	}
	if reader == nil {
		return fmt.Errorf("file not found. Does the zip contain %s ?", filepath.Base(savePath))
	}

	file, err := os.OpenFile(savePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(file, reader); err != nil {
		os.Remove(file.Name())
		return err
	}

	return nil
}

var builtinKeyring string = `
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=oseb
-----END PGP PUBLIC KEY BLOCK-----`
