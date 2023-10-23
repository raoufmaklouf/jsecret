package main

import (
	"bufio"
	"os"
	"sync"
)

var HashList = []string{}

func main() {
	var wg sync.WaitGroup
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {

		line := scanner.Text()
		if isUrl(line) == true {
			wg.Add(1)
			go func() {
				defer wg.Done()
				matcher(line)
			}()

		}

	}

	wg.Wait()

}
