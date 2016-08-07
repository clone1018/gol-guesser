package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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
	Cipher string
	Hash   string
	Result []byte
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	key := "tracer"

	ciphers := setupCiphers()
	hashes := setupHashes()

	var attempts = make([]AttemptResult, 0)

	for _, hash := range hashes {
		hashPath := path.Join("hashes", hash)

		cipherResults := attemptCiphers(ciphers, hashPath, key)

		for _, result := range cipherResults {
			attempts = append(attempts, result)
		}
	}

	b, err := json.Marshal(attempts)
	if err != nil {
		fmt.Println("error:", err)
	}
	os.Stdout.Write(b)
}

func attemptCiphers(ciphers []string, hashPath string, guess string) map[int]AttemptResult {
	messages := make(chan map[string][]byte)
	var wg sync.WaitGroup

	wg.Add(len(ciphers))

	for _, cipher := range ciphers {
		go func(hashPath string, guess string, cipher string) {
			defer wg.Done()

			result := make(map[string][]byte)

			out, err := attempt(hashPath, guess, cipher)
			if err != nil {
				panic(err)
			}

			result[cipher] = out

			messages <- result
		}(hashPath, guess, cipher)

	}

	results := make(map[int]AttemptResult)

	go func() {
		i := 0
		for response := range messages {
			for cipher, res := range response {

				results[i] = AttemptResult{
					Cipher: cipher,
					Hash:   hashPath,
					Result: res,
				}

				i++
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
	out, err := exec.Command("openssl", "ciphers").Output()
	if err != nil {
		panic(err)
	}

	return strings.Split(string(out), ":")

}

func setupHashes() map[int]string {
	hashes := make(map[int]string)

	files, err := ioutil.ReadDir("./hashes")
	if err != nil {
		log.Fatal(err)
	}

	i := 0
	for _, file := range files {
		hashes[i] = file.Name()
		i++
	}

	return hashes
}
