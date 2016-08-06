package main

import (
	"fmt"
	"io/ioutil"
	"path"
	"runtime"

	"log"
	"os/exec"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	cipher := "rc2-cfb"
	key := "tracer"

	file, err := saveGuess(key)
	if err != nil {
		panic(err)
	}

	hashPath := path.Join("hashes", "test.b64")
	fmt.Println(hashPath)

	out, err := exec.Command("openssl", cipher, "-d", "-a", "-in", hashPath, "-kfile", file).Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", out)
}

func saveGuess(guess string) (string, error) {
	content := []byte(guess)
	file, err := ioutil.TempFile("/tmp", "guess")
	if err != nil {
		log.Fatal(err)
		return "", err
	}

	_, err = file.Write(content)
	if err != nil {
		log.Fatal(err)
		return "", err
	}

	return file.Name(), nil
}
