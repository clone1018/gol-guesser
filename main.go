package main

import (
	"fmt"
	"log"
	"os/exec"
	"path"
	"runtime"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	cipher := "rc2-cfb"
	key := "&& ls"

	hashPath := path.Join("hashes", "test.b64")

	out, err := exec.Command("openssl", cipher, "-d", "-a", "-in", hashPath, "-pass", "pass:"+key).Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", out)
}
