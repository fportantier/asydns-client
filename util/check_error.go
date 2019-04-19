package util

import (
	"fmt"
	"os"
)

func CheckError(err error) {
	if err != nil {
		fmt.Println("Fata error ", err.Error())
		os.Exit(1)
	}
}
