package cache

import (
	"archive/tar"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// BaseCRL is the file name of the base CRL
	BaseCRLFile = "base.crl"

	// Metadata is the file name of the metadata
	MetadataFile = "metadata.json"
)

// CRLBlob contains CRL and metadata
type CRLBlob struct {
	BaseCRL  *x509.RevocationList
	Metadata Metadata
}

// Metadata stores the metadata infomation of the CRL
type Metadata struct {
	BaseCRL FileInfo `json:"base.crl"`
}

// FileInfo stores the URL and creation time of the file
type FileInfo struct {
	URL      string    `json:"url"`
	CreateAt time.Time `json:"createAt"`
}

// NewCRLBlob creates a new CRL store with tarball format
func NewCRLBlob(baseCRL *x509.RevocationList, url string) *CRLBlob {
	return &CRLBlob{
		BaseCRL: baseCRL,
		Metadata: Metadata{
			BaseCRL: FileInfo{
				URL:      url,
				CreateAt: time.Now(),
			},
		}}
}

// ParseCRLBlobFromTar parses the CRL blob from a tarball
func ParseCRLBlobFromTar(data io.Reader) (*CRLBlob, error) {
	crlBlob := &CRLBlob{}

	// parse the tarball
	tar := tar.NewReader(data)

	for {
		header, err := tar.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch header.Name {
		case BaseCRLFile:
			// parse base.crl
			data, err := io.ReadAll(tar)
			if err != nil {
				return nil, err
			}

			var baseCRL *x509.RevocationList
			baseCRL, err = x509.ParseRevocationList(data)
			if err != nil {
				return nil, err
			}

			crlBlob.BaseCRL = baseCRL
		case MetadataFile:
			// parse metadata
			var metadata Metadata
			if err := json.NewDecoder(tar).Decode(&metadata); err != nil {
				return nil, err
			}

			crlBlob.Metadata = metadata

		default:
			return nil, fmt.Errorf("unknown file in tarball: %s", header.Name)
		}
	}

	if crlBlob.BaseCRL == nil {
		return nil, errors.New("base.crl is missing")
	}

	if crlBlob.Metadata.BaseCRL.URL == "" {
		return nil, errors.New("base CRL's URL is missing from metadata.json")
	}

	return crlBlob, nil
}

// SaveAsTar saves the CRL blob as a tarball, including the base CRL and
// metadata
func (c *CRLBlob) SaveAsTar(w io.Writer) (err error) {
	tarWriter := tar.NewWriter(w)
	// Add base.crl
	if err := addToTar(BaseCRLFile, c.BaseCRL.Raw, tarWriter); err != nil {
		return err
	}

	// Add metadataBytes.json
	metadataBytes, err := json.Marshal(c.Metadata)
	if err != nil {
		return err
	}
	return addToTar(MetadataFile, metadataBytes, tarWriter)
}

func addToTar(fileName string, data []byte, tw *tar.Writer) error {
	header := &tar.Header{
		Name:    fileName,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
