// [_Command-line flags_](http://en.wikipedia.org/wiki/Command-line_interface#Command-line_option)
// are a common way to specify options for command-line
// programs. For example, in `wc -l` the `-l` is a
// command-line flag.

package main

// Go provides a `flag` package supporting basic
// command-line flag parsing. We'll use this package to
// implement our example command-line program.
import "flag"
import "fmt"
import "os/user"
import "os"
import "log"
import "crypto/rand"
import "crypto/rsa"
import "crypto/x509"
import "encoding/asn1"
import "encoding/pem"
import "net/http"
import "io/ioutil"
import "encoding/json"
import "encoding/base64"
import "errors"
import "crypto/sha256"
import "crypto"
import "bytes"
//import "strings"

func main() {

    optUrl := flag.String("url", "https://asydns.org", "API URL")
    optRevoke := flag.Bool("revoke", false, "Revoke the current key")
    optGenerate := flag.Bool("generate", false, "Force the generation of a new key")
    optVerbose := flag.Bool("verbose", false, "Verbose output")

    flag.Parse()

    usr, err := user.Current()
    if err != nil {
        log.Fatal( err )
    }
    fmt.Println( usr.HomeDir )

    separator := string(os.PathSeparator)

    pubPath := usr.HomeDir + separator + ".asydns.pub"
    privPath := usr.HomeDir + separator + ".asydns.key"

    fmt.Println(pubPath)
    fmt.Println(privPath)

    if *optGenerate || ! fileExists(pubPath) || ! fileExists(privPath) {
        generateKeyPair(privPath, pubPath)
    }

    pubPEM, err := ioutil.ReadFile(pubPath)
    privPEM, err := ioutil.ReadFile(privPath)

    //privKey, err := parsePrivateKey(privPEM)

    challenge, err := getChallenge(*optUrl)

    if err != nil {
        log.Print("Error on challenge")
    }


    decoded_challenge, err := base64.StdEncoding.DecodeString(challenge)

    signer, err := parsePrivateKey(privPEM)

    signed_challenge, err := signer.Sign(decoded_challenge)


    signed_challenge_b64 := base64.StdEncoding.EncodeToString([]byte(signed_challenge))


    fmt.Println(challenge)
    fmt.Println(signed_challenge)
    fmt.Println(signed_challenge_b64)
    fmt.Println(*optRevoke)
    fmt.Println(*optVerbose)

    _ = asydnsUpdate(*optUrl, string(pubPEM), challenge, signed_challenge_b64, *optRevoke)

}




func savePrivatePEM(fileName string, key *rsa.PrivateKey) {
    outFile, err := os.Create(fileName)
    checkError(err)
    defer outFile.Close()

    var privateKey = &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(key),
    }

    err = pem.Encode(outFile, privateKey)
    checkError(err)
}


func savePublicPEM(fileName string, pubkey rsa.PublicKey) {
    asn1Bytes, err := asn1.Marshal(pubkey)
    checkError(err)

    var pemkey = &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: asn1Bytes,
    }

    pemfile, err := os.Create(fileName)
    checkError(err)
    defer pemfile.Close()

    err = pem.Encode(pemfile, pemkey)
    checkError(err)
}



func checkError(err error) {
    if err != nil {
        fmt.Println("Fatal error ", err.Error())
        os.Exit(1)
    }
}

// Exists reports whether the named file or directory exists.
func fileExists(name string) bool {
    if _, err := os.Stat(name); err != nil {
        if os.IsNotExist(err) {
            return false
        }
    }
    return true
}



func generateKeyPair(privPath string, pubPath string) (error) {

    log.Print("Generating public and private keys...")
    reader := rand.Reader
    bitSize := 2048

    privKey, err := rsa.GenerateKey(reader, bitSize)
    checkError(err)

    pubKey := privKey.PublicKey

    savePublicPEM(pubPath, pubKey)
    savePrivatePEM(privPath, privKey)

    return nil
} 


func getChallenge(url string) (challenge string, err error) {

    resp, err := http.Get(url + "/api")

    if err != nil {
        log.Print("An error has been ocurred")
    }

    defer resp.Body.Close()

    bodyBytes, err := ioutil.ReadAll(resp.Body)
    body := string(bodyBytes)

    var result map[string]string

    err = json.Unmarshal([]byte(body), &result)

    if err != nil {
        log.Print("Error decoding challenge!")
    }

    fmt.Printf("Challenge: %+v\n", result["challenge"])

    return result["challenge"], nil
}


// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}


func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha224
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New224()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA224, d)
}



func asydnsUpdate(url, public_pem, challenge, signed_challenge string, revoke bool) (error){

    type Message struct {
        Pub string `json:"pub"`
        Challenge string `json:"challenge"`
        Response string `json:"response"`
    }

    message := &Message{ Pub : public_pem, Challenge : challenge, Response : signed_challenge }
    message_json, err := json.Marshal(message)

    if err != nil {
        log.Print("Error decoding challenge!")
    }

    fmt.Print("JSON a enviar:")
    fmt.Println(string(message_json))

    req, err := http.NewRequest("POST", url + "/api", bytes.NewBuffer(message_json))
    //req.Header.Set("X-Custom-Header", "myvalue")
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Println("response Status:", resp.Status)
    fmt.Println("response Headers:", resp.Header)
    body, _ := ioutil.ReadAll(resp.Body)
    fmt.Println("response Body:", string(body))
    return nil
}






