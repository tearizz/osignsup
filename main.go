package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

var CommonPrivateKey string
var CommonPublicKey string
var CommonSignature string

const DIGEST = "Hello, Signatom!"

// Request Structure
type BaseConfig struct {
	Algo string `json:"algo"`
	Kms  string `json:"kms"`
	Flow string `json:"flow"`
}
type GenerateKeyRequest BaseConfig

type SignwithKeyRequest struct {
	BaseConfig `json:"base_config"`
	PrivateKey string `json:"priv"`
	DigestData string `json:"digest"`
}

type VerifywithKeyRequest struct {
	BaseConfig `json:"base_config"`
	PublicKey  string `json:"pub"`
	DigestData string `json:"digest"`
	Signature  string `json:"signature"`
}

// Response Structure
type GenerateKeyResponse struct {
	BaseConfig `json:"base_conig"`
	PrivateKey string `json:"priv"`
	PublicKey  string `json:"pub"`
	KeyId      string `json:"key_id"`
}

type SignwithKeyResponse struct {
	BaseConfig `json:"base_config"`
	Signature  string `json:"signature"`
	Cert       string `json:"cert"`
}

type VerifywithKeyResponse struct {
	BaseConfig `json:"base_config"`
	Result     string `json:"result"`
}

func main() {

	http.HandleFunc("/generateKey", keyGenerationHandler)
	http.HandleFunc("/signwithKey", signwithKeyHandler)
	http.HandleFunc("/verifywithKey", verifywithKeyHandler)

	log.Println("Key Generation Proxy started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func verifywithKeyHandler(w http.ResponseWriter, r *http.Request) {
	// check received method
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusInternalServerError)
	}

	//check parameters
	if len(CommonSignature) == 0 || len(CommonPublicKey) == 0 || len(DIGEST) == 0 {
		http.Error(w, "signature or public key or digest is not set", http.StatusInternalServerError)
		return
	}

	// construct the request body with fixed parameters
	verifywithKeyRequest := VerifywithKeyRequest{
		BaseConfig: BaseConfig{
			Algo: "sm2",
			Kms:  "",
			Flow: "classic",
		},
		PublicKey:  CommonPublicKey,
		DigestData: DIGEST,
		Signature:  CommonSignature,
	}

	reqBody, err := json.Marshal(verifywithKeyRequest)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// create a timeout HTTP client (5 seconds timeout)
	client := &http.Client{Timeout: 5 * time.Second}

	targetURL := "http://10.20.173.8:80/v1/verify/digest"
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("Request creation error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VerifywithKey/1.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("API request failed: %v", err)
		http.Error(w, "Backend service unavailable", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Response read error: %v", err)
		http.Error(w, "Error reading backend response", http.StatusInternalServerError)
		return
	}

	var vr VerifywithKeyResponse
	err = json.Unmarshal(body, &vr)
	if err != nil {
		log.Printf("Response parse error: %v", err)
		http.Error(w, "Error parsing backend response", http.StatusInternalServerError)
		return
	}

	log.Printf("Backend API response - Status: %d, Body: %s", string(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func signwithKeyHandler(w http.ResponseWriter, r *http.Request) {

	// Check received method
	if r.Method != http.MethodGet {
		http.Error(w,
			"Only GET method is allowed", http.StatusMethodNotAllowed)
	}

	// check common private key
	if CommonPrivateKey == "" {
		http.Error(w, "Common private key is not set", http.StatusInternalServerError)
		return
	}

	// Construct the request body with fixed parameters
	signwithKeyRequest := SignwithKeyRequest{
		BaseConfig: BaseConfig{
			Algo: "sm2",
			Kms:  "", // Empty string
			Flow: "classic",
		},
		PrivateKey: CommonPrivateKey,
		DigestData: DIGEST, // Replace with actual digest data
	}

	// Convert to JSON
	reqBody, err := json.Marshal(signwithKeyRequest)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create a timeout HTTP client (5 seconds timeout)
	client := &http.Client{Timeout: 5 * time.Second}

	// Create the target API request
	targetURL := "http://10.20.173.8:80/v1/sign/digest"
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("Request creation error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SignwithKey/1.0")

	// send request
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("API request failed: %v", err)
		http.Error(w, "Backend service unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read and Parse Response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Response read error: %v", err)
		http.Error(w, "Error reading backend response", http.StatusInternalServerError)
		return
	}

	var sr SignwithKeyResponse
	err = json.Unmarshal(body, &sr)
	if err != nil {
		log.Printf("Response parse error: %v", err)
		http.Error(w, "Error reading backend response", http.StatusInternalServerError)
		return
	}

	CommonSignature = sr.Signature

	// log response
	log.Printf("Backend API response - Status: %d, Body: %s", string(body))

	// return target response data to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func keyGenerationHandler(w http.ResponseWriter, r *http.Request) {
	// check GET method
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// construct the request with fixed parameters
	targetReq := GenerateKeyRequest{
		Algo: "sm2",
		Kms:  "",
		Flow: "classic",
	}

	// convert struct to json
	reqBody, err := json.Marshal(targetReq)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// create a timeout HTTP client (5 seconds timeout)
	client := &http.Client{Timeout: 5 * time.Second}

	// create the target API request
	targetURL := "http://10.20.173.8:80/v1/keypair"
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("Request creation error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "KeyGenerationProxy/1.0")

	// send request
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("API request failed: %v", err)
		http.Error(w, "Backend service unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Response read error: %v", err)
		http.Error(w, "Error reading backend response", http.StatusInternalServerError)
		return
	}

	var gr GenerateKeyResponse
	err = json.Unmarshal(body, &gr)
	if err != nil {
		log.Printf("Response parse error: %v", err)
		http.Error(w, "Error parsing backend response", http.StatusInternalServerError)
		return
	}

	CommonPrivateKey = gr.PrivateKey
	CommonPublicKey = gr.PublicKey

	// log response
	log.Printf("Backend API response - Status: %d, Body: %s", resp.StatusCode, string(body))

	// return target response data to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}
