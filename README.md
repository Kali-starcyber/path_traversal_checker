# 🛡 Path Traversal Scanner (Go)

A fast, concurrent path traversal vulnerability scanner written in Go.

## 🔍 Features

- 🚀 Concurrent scanning for speed
- ✅ Highlights vulnerable URLs in green
- ❌ Non-vulnerable URLs in red
- 🔐 Supports Authorization headers
- 📄 Saves results to `vulnerable.txt`
- 📂 Accepts a list of subdomains/URLs from a `.txt` file

---

## 🛠 Requirements

- [Go](https://golang.org/doc/install) (v1.18+)
- Go modules enabled

Install Go:
```bash
sudo apt install golang


📦 Installation

git clone https://github.com/Kali-starcyber/path_traversal_checker.git
cd path-traversal-go
go mod init path-traversal
go get github.com/fatih/color


📄 Usage

1. Add your targets to subdomains.txt (one per line):

https://example.com
http://api.example.com

2. Run the scanner:

go run path_traversal_checker.go /path/subdomains.txt


