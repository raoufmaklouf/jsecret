package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"
)

var HachList = []string{}

func main() {
	var wg sync.WaitGroup
	scanner := bufio.NewScanner(os.Stdin)

	c := make(chan struct{}, 100)
	for scanner.Scan() {
		wg.Add(1)

		line := scanner.Text()
		if isUrl(line) == true {
			go mutcher(line, c, &wg)
			time.Sleep(20 * time.Millisecond)

		}

	}

	wg.Wait()
	go func() {

		close(c)
	}()
	for msg := range c {
		fmt.Println(msg)
	}
}

func mutcher(url string, c chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	response := requester(url)
	if response != "" {
		Hach, _ := CreatHashSum(response)
		if contains(HachList, Hach) == false {
			HachList = append(HachList, Hach)
			for k, p := range regex {
				rgx := regexp.MustCompile(p)
				found := rgx.MatchString(response)
				if found {
					mt := rgx.FindStringSubmatch(response)
					a := mt[0]
					fmt.Printf("%s  \033[32m  %s : %s \033[00m\n", url, k, a)
					<-c
				}

			}

		}

	}

}
