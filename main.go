package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"gopkg.in/urfave/cli.v1"
)

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

	app := cli.NewApp()
	app.Name = "gol-guesser"
	app.Usage = "Attempt password guesses against the Sombra ARG summer games crypto!"
	app.Version = "1.0.0"
	app.Commands = []cli.Command{
		{
			Name:  "web",
			Usage: "Start up the API webserver",
			Action: func(c *cli.Context) error {

				ws := WebServer{
					Port: "8080",
				}
				ws.Start()

				return nil
			},
		},
		{
			Name:  "guess",
			Usage: "Attempt a guess on the command line",
			Flags: []cli.Flag{
				cli.BoolTFlag{
					Name:  "all-ciphers",
					Usage: "All ciphers",
				},
			},
			Action: func(c *cli.Context) error {
				attempts := AttemptGuess(c.Args().First(), c.BoolT("all-ciphers"))

				for _, attempt := range attempts {
					fmt.Printf("%s - %s: %s \n", attempt.HashFile, attempt.Cipher, attempt.Result)
				}

				return nil
			},
		},
	}

	app.Run(os.Args)

	/*
		http.HandleFunc("/", processGuess)
		http.ListenAndServe(":8000", nil)
	*/
}

func AttemptGuess(guess string, allCiphers bool) []DecryptResult {
	var ciphers []string
	if allCiphers == true {
		ciphers = AllCiphers
	} else {
		ciphers = RecommendedCiphers
	}

	var attempts = make([]DecryptResult, 0)

	for _, hash := range Hashes {
		hashPath := path.Join("hashes", hash)

		decrypter := Decrypt{
			Ciphers:  ciphers,
			HashPath: hashPath,
		}

		cipherResults := decrypter.Attempt(guess)

		for _, result := range cipherResults {
			attempts = append(attempts, result)
		}
	}

	return attempts
}

func processGuess(w http.ResponseWriter, r *http.Request) {
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
