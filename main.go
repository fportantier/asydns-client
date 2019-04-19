package main

import (
	"encoding/base64"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/user"

	"asydns-client/asydns"
	"asydns-client/util"
	"asydns-client/xcrypto"
)

func main() {

	optURL := flag.String("url", "https://asydns.org", "API URL")
	optRevoke := flag.Bool("revoke", false, "Revoke the current key")
	optGenerate := flag.Bool("generate", false, "Force the generation of a new key")
	optVerbose := flag.Bool("verbose", false, "Verbose output")

	flag.Parse()

	log.SetOutput(ioutil.Discard)

	if *optVerbose {
		log.SetOutput(os.Stderr)
	}

	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	separator := string(os.PathSeparator)

	pubPath := usr.HomeDir + separator + ".asydns.pub"
	privPath := usr.HomeDir + separator + ".asydns.key"

	if *optGenerate || !util.FileExists(pubPath) || !util.FileExists(privPath) {
		log.Print("Generating key pair...")
		xcrypto.GenerateKeyPair(privPath, pubPath)
	}

	pubPEM, err := ioutil.ReadFile(pubPath)
	privPEM, err := ioutil.ReadFile(privPath)

	log.Print("Obtaining challenge...")
	challenge, err := asydns.GetChallenge(*optURL)

	if err != nil {
		log.Print("Error on challenge")
	}

	log.Print("Decoding challenge...")
	decodedChallenge, err := base64.StdEncoding.DecodeString(challenge)

	signer, err := xcrypto.ParsePrivateKey(privPEM)

	log.Print("Signing challenge...")
	signedChallenge, err := signer.Sign(decodedChallenge)

	signedChallengeB64 := base64.StdEncoding.EncodeToString([]byte(signedChallenge))

	log.Print("Sending upated request...")
	err = asydns.Update(*optURL, string(pubPEM), challenge, signedChallengeB64, *optRevoke)

}
