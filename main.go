package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"sync"
)

type Output struct {
	Results []AttemptResult
}

type AttemptResult struct {
	Cipher       string
	HashBase64   string
	HashFile     string
	ResultBase64 []byte
}

var AllCiphers []string
var RecommendedCiphers = []string{
	"AES-128-CFB",
	"AES-128-CFB1",
	"AES-128-CFB8",
	"AES-128-CTR",
	"AES-128-OFB",
	"AES-192-CFB",
	"AES-192-CFB1",
	"AES-192-CFB8",
	"AES-192-CTR",
	"AES-192-OFB",
	"AES-256-CFB",
	"AES-256-CFB1",
	"AES-256-CFB8",
	"AES-256-CTR",
	"AES-256-OFB",
	"BF-CFB",
	"BF-OFB",
	"CAST5-CFB",
	"CAST5-OFB",
	"DES-CFB",
	"DES-CFB1",
	"DES-CFB8",
	"DES-EDE-CFB",
	"DES-EDE-OFB",
	"DES-EDE3-CFB",
	"DES-EDE3-CFB1",
	"DES-EDE3-CFB8",
	"DES-EDE3-OFB",
	"DES-OFB",
	"IDEA-CFB",
	"IDEA-OFB",
	"RC2-CFB",
	"RC2-OFB",
	"RC4",
	"RC4-40",
	"SEED-CFB",
	"SEED-OFB",
	"id-aes128-CCM",
	"id-aes192-CCM",
	"id-aes256-CCM",
}
var Hashes []string

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	AllCiphers = setupCiphers()
	Hashes = setupHashes()

	http.HandleFunc("/", processGuess)
	http.ListenAndServe(":8000", nil)
}

func processGuess(w http.ResponseWriter, r *http.Request) {
	passwordArg := r.URL.Query().Get("password")
	ciphersArg := r.URL.Query().Get("ciphers")

	var ciphers []string
	if ciphersArg == "all" {
		ciphers = AllCiphers
	} else {
		ciphers = RecommendedCiphers
	}

	var attempts = make([]AttemptResult, 0)

	for _, hash := range Hashes {
		hashPath := path.Join("hashes", hash)

		cipherResults := attemptCiphers(ciphers, hashPath, passwordArg)

		for _, result := range cipherResults {
			attempts = append(attempts, result)
		}
	}

	b, err := json.Marshal(attempts)
	if err != nil {
		log.Println(err)
	}

	io.WriteString(w, string(b))
}

func attemptCiphers(ciphers []string, hashPath string, guess string) []AttemptResult {
	messages := make(chan map[string][]byte)
	var wg sync.WaitGroup

	wg.Add(len(ciphers))

	for _, cipher := range ciphers {
		go func(hashPath string, guess string, cipher string) {
			defer wg.Done()

			result := make(map[string][]byte)

			out, _ := attempt(hashPath, guess, cipher)

			result[cipher] = out

			messages <- result
		}(hashPath, guess, cipher)

	}

	results := make([]AttemptResult, 0)

	go func() {
		for response := range messages {
			for cipher, res := range response {
				results = append(results, AttemptResult{
					Cipher:       cipher,
					HashFile:     hashPath,
					ResultBase64: res,
				})
			}
		}
	}()

	wg.Wait()
	return results
}

func attempt(hashPath string, guess string, cipher string) ([]byte, error) {
	return exec.Command("openssl", cipher, "-d", "-a", "-in", hashPath, "-pass", "pass:"+guess).Output()
}

func setupCiphers() []string {
	out, err := exec.Command("openssl", "list-cipher-algorithms").Output()
	if err != nil {
		log.Println(err)
	}

	ciphers := make([]string, 0)
	for _, cipher := range strings.Split(string(out), "\n") {
		if strings.Contains(cipher, " => ") == false {
			ciphers = append(ciphers, cipher)
		}
	}

	return ciphers

}

func setupHashes() []string {
	hashes := make([]string, 0)

	files, err := ioutil.ReadDir("./hashes")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		hashes = append(hashes, file.Name())
	}

	return hashes
}
