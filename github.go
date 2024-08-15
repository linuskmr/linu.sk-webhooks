package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
)

// GitHubWebhookPayload represents the payload of a GitHub webhook event,
// according to https://docs.github.com/en/webhooks/webhook-events-and-payloads#example-webhook-delivery.
// It is used to decode the JSON payload of a GitHub webhook event.
type GitHubWebhookPayload struct {
	Repository GitHubWebhookRepository
}

// GitHubWebhookRepository is a part of [GitHubWebhookPayload]
type GitHubWebhookRepository struct {
	Name string `json:"name"`
}

// Github handles webhooks from GitHub.
func Github(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Println("Error reading request body:", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var jsonBody GitHubWebhookPayload
	err = json.Unmarshal(body, &jsonBody)
	if err != nil {
		log.Println("Cannot decode body as json:", err)
		http.Error(w, "Cannot decode body as json", http.StatusBadRequest)
		return
	}

	if !isSignatureValid(body, req.Header) {
		log.Printf("Invalid HMAC signature provided in X-Hub-Signature-256 header for repository %s", jsonBody.Repository.Name)
		http.Error(w, "Invalid HMAC signature provided in X-Hub-Signature-256 header", http.StatusForbidden)
		return
	}

	// Do our best to avoid path traversal attacks (although signed from Github; you never know)
	if !isValidRepositoryName(jsonBody.Repository.Name) {
		log.Println("Invalid repository name:", jsonBody.Repository.Name)
		http.Error(w, "Invalid repository name", http.StatusBadRequest)
		return
	}

	folderName := jsonBody.Repository.Name
	suffix := ".linu.sk"
	if !strings.HasSuffix(folderName, suffix) {
		folderName += suffix
	}

	// Do our best to avoid path traversal attacks 2.0 (from signed from Github; you never know)
	parentWorkdir := "/var/www/"
	workdir := path.Clean(path.Join(parentWorkdir, folderName))
	if !strings.HasPrefix(workdir, parentWorkdir) || workdir == parentWorkdir {
		log.Printf("Invalid folder name %s for repository\n", workdir)
		http.Error(w, "Invalid folder name for repository", http.StatusBadRequest)
		return
	}

	// Pull the repository
	cmd := exec.Command("git", "pull")
	cmd.Dir = workdir
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed pulling repository %s: %s %s\n", workdir, string(output), err)
		log.Println("Note: If this results in the error 'detected dubious ownership in repository', there is a conflict between the owner of the repository and the user running 'git pull' through this service. To fix this, transfer the ownership of the repository to the user using 'sudo chown -R www-data .' and 'git config --global --add safe.directory REPO_PATH' to also let others user do a 'git pull' there.")
		http.Error(w, "Failed to pull repository", http.StatusInternalServerError)
		return
	}

	if _, err := os.Stat(path.Join(workdir, "Makefile")); errors.Is(err, os.ErrNotExist) {
		log.Printf("No Makefile found in folder %s. Therefore don't gonna build anything, but is pulled/is up-to-date :)\n", workdir)
		return
	}


	// Build repository
	cmd = exec.Command("make", "build")
	cmd.Dir = workdir
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Failed building repository %s: %s %s\n", workdir, string(output), err)
		http.Error(w, "Failed to build repository", http.StatusInternalServerError)
		return
	}
}


// isSignatureValid checks whether the provided signature in the X-Hub-Signature-256 HTTP header matches the HMAC-SHA256 signature of the request body.
//
// See https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#validating-webhook-deliveries
func isSignatureValid(body []byte, requestHeaders http.Header) bool {
	// Get and parse HMAC signature from header
	providedHmacString := requestHeaders.Get("X-Hub-Signature-256")
	providedHmacString, _ = strings.CutPrefix(providedHmacString, "sha256=")
	providedHmacBytes, err := hex.DecodeString(providedHmacString)
	if err != nil {
		log.Println("isSignatureValid: Couldn't decode X-Hub-Signature-256 header as hex:", err)
		return false
	}

	// Compute HMAC signature of request body
	secret := os.Getenv("GITHUB_SECRET")
	bodyHmacComputation := hmac.New(sha256.New, []byte(secret))
	bodyHmacComputation.Write(body)
	computedBodyHmac := bodyHmacComputation.Sum(nil)

	// Constant-time comparison to avoid timing attacks
	return hmac.Equal(providedHmacBytes, computedBodyHmac)
}


func isValidRepositoryName(str string) bool {
	// Only ASCII letters, digits, and '.' are allowed
	for _, chr := range str {
		isAsciiLowercaseLetter := chr >= 'a' && chr <= 'z'
		isAsciiUppercaseLetter := chr >= 'A' && chr <= 'Z'
		isDigit := chr >= '0' && chr <= '9'
		isAllowedSpecial := chr == '.' || chr == '-' || chr == '_'
		if !isAsciiLowercaseLetter && !isAsciiUppercaseLetter && !isDigit && !isAllowedSpecial {
			return false
		}
	}

	hasPathTraversal := strings.Contains(str, "..")
	if hasPathTraversal {
		return false
	}

	return true
}