package main

import (
	"os/exec"
	"sync"
	"unicode/utf8"
)

type Decrypt struct {
	Ciphers  []string
	HashPath string
}

type DecryptResult struct {
	Cipher          string
	HashBase64      string
	HashFile        string
	HumanCharacters int
	Result          []byte
}

func (d *Decrypt) Attempt(guess string) []DecryptResult {
	messages := make(chan map[string][]byte)
	var wg sync.WaitGroup

	wg.Add(len(d.Ciphers))

	for _, cipher := range d.Ciphers {
		go func(hashPath string, guess string, cipher string) {
			defer wg.Done()

			result := make(map[string][]byte)

			out, _ := d.opensslDecrypt(cipher, hashPath, guess)

			result[cipher] = out

			messages <- result
		}(d.HashPath, guess, cipher)

	}

	results := make([]DecryptResult, 0)

	go func() {
		for response := range messages {
			for cipher, res := range response {

				_, size := utf8.DecodeLastRuneInString(string(res))
				results = append(results, DecryptResult{
					Cipher:          cipher,
					HashFile:        d.HashPath,
					Result:          res,
					HumanCharacters: size,
				})
			}
		}
	}()

	wg.Wait()
	return results
}

func (d *Decrypt) opensslDecrypt(cipher string, hashPath string, guess string) ([]byte, error) {
	return exec.Command("openssl", cipher, "-d", "-a", "-in", hashPath, "-pass", "pass:"+guess).Output()
}
