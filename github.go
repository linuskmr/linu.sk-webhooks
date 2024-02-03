package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
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
	FullName string `json:"full_name"`
}

// Github handles webhooks from GitHub.
func Github(w http.ResponseWriter, req *http.Request) {
	// Read the whole request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Println("Error reading request body:", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	if !isSignatureValid(body, req.Header) {
		log.Println("Invalid HMAC signature provided in X-Hub-Signature-256 header")
		http.Error(w, "Invalid HMAC signature provided in X-Hub-Signature-256 header", http.StatusBadRequest)
		return
	}

	// Decode body as JSON
	var jsonBody GitHubWebhookPayload
	err = json.Unmarshal(body, &jsonBody)
	if err != nil {
		log.Println("Cannot decode body as json:", err)
		http.Error(w, "Cannot decode body as json", http.StatusBadRequest)
		return
	}

	switch jsonBody.Repository.FullName {
	case "linuskmr/linu.sk":
		wwwLinusk(w)
	default:
		log.Println("Received push event for unknown repository:", jsonBody.Repository.FullName)
		http.Error(w, "Received push event for unknown repository", http.StatusBadRequest)
		return
	}
}

// wwwLinusk updates and builds the linu.sk website.
func wwwLinusk(w http.ResponseWriter) {
	// Pull repository
	// Note: If this results in the error 'detected dubious ownership in repository',
	// there is a conflict between the owner of the repository and the user running 'git pull'
	// through this service. To fix this, transfer the ownership of the repository to the user
	// using 'sudo chown -R www-data .' and 'git config --global --add safe.directory REPO_PATH'
	// to also let others user do a 'git pull' there.
	workdir := "/var/www/www.linu.sk"
	cmd := exec.Command("git", "pull")
	cmd.Dir = workdir
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("Failed pulling linuskmr/linu.sk:", string(output), err)
		http.Error(w, "Failed to update repository", http.StatusInternalServerError)
		return
	}

	// Build website
	cmd = exec.Command("make", "build")
	cmd.Dir = workdir
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Println("Failed building website linuskmr/linu.sk:", string(output), err)
		http.Error(w, "Failed to build website", http.StatusInternalServerError)
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
