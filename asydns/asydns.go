package asydns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func GetChallenge(url string) (challenge string, err error) {

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

	return result["challenge"], nil
}

func Update(url, publicPEM, challenge, signedChallenge string, revoke bool) error {

	type Message struct {
		Pub       string `json:"pub"`
		Challenge string `json:"challenge"`
		Response  string `json:"response"`
	}

	message := &Message{Pub: publicPEM, Challenge: challenge, Response: signedChallenge}
	messageJSON, err := json.Marshal(message)

	if err != nil {
		log.Print("Error decoding challenge!")
	}

	method := "POST"

	if revoke == true {
		method = "DELETE"
	}

	req, err := http.NewRequest(method, url+"/api", bytes.NewBuffer(messageJSON))

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	fmt.Println(string(body))

	return nil
}
