package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/PuerkitoBio/goquery"
)

const (
	CertsDir   = "certs"
	AppleCaURL = "https://www.apple.com/certificateauthority/"
)

type Link struct {
	Name string
	URL  string
}

type AppleCALinks struct {
	Roots         []Link
	Intermediates []Link
}

func main() {
	fmt.Println("Remove existing certs...")
	if err := os.RemoveAll(CertsDir); err != nil {
		log.Fatalf("Error removing certs dir: %v", err)
	}

	fmt.Println("Downloading Apple CA index page...")
	by, err := download(AppleCaURL)
	if err != nil {
		log.Fatalf("Error reading URL: %v", err)
	}

	// for casual testing
	// by, err := os.ReadFile("test-fixtures/index.html")
	// if err != nil {
	//  	log.Fatalf("Error reading file: %v", err)
	// }

	fmt.Println("Parsing Apple CA index page...")
	appleCALinks, err := findCALinks(by, AppleCaURL)
	if err != nil {
		log.Fatalf("Error finding Apple CA links: %v", err)
	}

	fmt.Println("Apple root certificates:")
	for _, link := range appleCALinks.Roots {
		fmt.Println("  -", link.URL)
		if err := downloadCertTo(link.URL, path.Join(CertsDir, "root")); err != nil {
			log.Fatalf("Error downloading root cert %s: %v", link.URL, err)
		}
	}

	fmt.Println("\nApple intermediate certificates:")
	for _, link := range appleCALinks.Intermediates {
		fmt.Println("  -", link.URL)
		if err := downloadCertTo(link.URL, path.Join(CertsDir, "intermediate")); err != nil {
			log.Fatalf("Error downloading intermediate cert %s: %v", link.URL, err)
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting current working directory: %v", err)
	}
	fmt.Printf("\nDone!\nCertificates saved to %q\n", path.Join(cwd, CertsDir))
}

func mkdirs(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}

func downloadCertTo(url, dest string) error {
	if err := mkdirs(dest); err != nil {
		return err
	}

	by, err := download(url)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, bytes.NewReader(by))
	if err != nil {
		return err
	}

	// check that the content is a PEM encoded certificate or if is a DER encoded certificate
	var suffix string
	if len(buf.Bytes()) > 0 && buf.Bytes()[0] == 0x30 {
		// convert the DER encoded certificate in "buf" to PEM
		pemBy := convertDERToPEM(buf.Bytes())

		buf = bytes.NewBuffer(pemBy)
	}

	if bytes.HasPrefix(buf.Bytes(), []byte("-----BEGIN CERTIFICATE-----")) {
		suffix = ".pem"
	}

	if suffix == "" {
		return fmt.Errorf("unknown certificate format")
	}

	basename := path.Base(url)
	basename = basename[:len(basename)-len(path.Ext(basename))] + suffix
	filepath := path.Join(dest, basename)

	// open a file for writing
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// write the body to file
	_, err = io.Copy(out, buf)
	if err != nil {
		return err
	}

	return nil
}

func convertDERToPEM(der []byte) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return pem.EncodeToMemory(block)
}

func download(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec // G107 is a false positive since the URL is a constant
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func findCALinks(html []byte, url string) (*AppleCALinks, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(html))
	if err != nil {
		return nil, fmt.Errorf("unable to parse HTML: %w", err)
	}

	// Find the <div> containing the Apple root certificates
	rootDiv := doc.Find("div > h2:contains('Apple Root Certificates')").Parent()

	// Extract links from the table in the <div>
	rootLinks := extractCertLinks(rootDiv, url)

	// Find the <div> containing the Apple intermediate certificates
	intermediateDiv := doc.Find("div > h2:contains('Apple Intermediate Certificates')").Parent()

	// Extract links from the table in the <div>
	intermediateLinks := extractCertLinks(intermediateDiv, url)

	return &AppleCALinks{
		Roots:         rootLinks,
		Intermediates: intermediateLinks,
	}, nil
}

// Extracts links from the table rows in the given goquery selection
func extractCertLinks(selection *goquery.Selection, u string) []Link {
	var links []Link

	parsedURL, err := url.Parse(u)
	if err != nil {
		log.Fatalf("Error parsing URL: %v", err)
	}

	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	// Find all <tr> elements in the selection
	selection.Find("li").Each(func(i int, row *goquery.Selection) {
		// Find the <a> element in the first <td> in the row
		link := row.Find("a")

		// Extract the href attribute from the <a> element
		href, exists := link.Attr("href")

		// if href starts with a slash, prepend the url
		if exists && href[0] == '/' {
			href = baseURL + href
		}

		if exists {
			links = append(links, Link{
				Name: link.Text(),
				URL:  href,
			})
		}
	})

	return links
}
