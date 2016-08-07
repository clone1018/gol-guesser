package main

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

var HumanRegex = regexp.MustCompile(`[ -~]`)
var WordRegex = regexp.MustCompile(`\w+`)

type Decrypt struct {
	Ciphers  []string
	HashPath string
	Results  DecryptResults
}

type DecryptResult struct {
	Cipher       string
	HashBase64   string
	HashFile     string
	Rank         float64
	Result       []byte
	ResultString string
}

type DecryptResults []DecryptResult

func (slice DecryptResults) Len() int {
	return len(slice)
}

func (slice DecryptResults) Less(i, j int) bool {
	return slice[i].Rank > slice[j].Rank
}

func (slice DecryptResults) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (d *Decrypt) Attempt(guess string) DecryptResults {
	//messages := make(chan map[string][]byte)
	var wg sync.WaitGroup

	wg.Add(len(d.Ciphers))

	results := make(DecryptResults, 0)

	for _, cipher := range d.Ciphers {
		go func(hashPath string, guess string, cipher string) {
			defer wg.Done()

			rank := 0.00

			out, err := d.opensslDecrypt(cipher, hashPath, guess)
			if err == nil {
				rank += 1.00
			}

			stringOut := strings.Trim(string(out), "\n")
			printable := AsciiPrintable(stringOut)

			if WordRegex.MatchString(stringOut) {
				rank += 1.00
			}

			add, _ := strconv.ParseFloat("0."+strconv.Itoa(printable), 64)
			rank += add

			diff := len(stringOut) - printable
			sub, _ := strconv.ParseFloat("0."+strconv.Itoa(diff), 64)
			rank -= sub

			// This is it!
			if printable == len(stringOut) {
				rank = 5.00
			}

			if stringOut == "" {
				rank = 0.00
			}

			results = append(results, DecryptResult{
				Cipher:       cipher,
				HashFile:     d.HashPath,
				Result:       out,
				ResultString: stringOut,
				Rank:         rank,
			})
		}(d.HashPath, guess, cipher)

	}

	wg.Wait()
	return results
}

func (d *Decrypt) opensslDecrypt(cipher string, hashPath string, guess string) ([]byte, error) {
	return exec.Command("openssl", cipher, "-d", "-a", "-in", hashPath, "-pass", "pass:"+guess).Output()
}

func AsciiPrintable(s string) int {
	count := 0
	for _, r := range s {
		if unicode.IsPrint(r) && r < unicode.MaxASCII {
			count++
		}

	}
	return count
}
