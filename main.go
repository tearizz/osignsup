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

var CommonCertificate Certificate

const DIGEST = "Hello, Signatom!"
const IDTOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlNIN1RtRnRQUVRJQzJqTHhpYTJ2UGV3VjVvaUxrcEhpYUVwbDFLTXA5SnMifQ.eyJhdWQiOlsic2lnc3RvcmUiXSwiZXhwIjoxNzI0NzUxNDMwLCJpYXQiOjE3MjQ3NTA4MzAsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJnZXR0b2tlbi0wMDAwMS1kZXBsb3ltZW50LTdmOTlkN2JjODgtcHo5OXIiLCJ1aWQiOiI5MTE4NTMwMy0zZjhlLTRhMGYtOTQzMC0yYWQ3MjQ0YmFmOWQifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImRlZmF1bHQiLCJ1aWQiOiI2Y2NhZTZmMi00MmQ4LTRiMDUtOTVhZS1jMDdhNzk5ZDQyNjkifX0sIm5iZiI6MTcyNDc1MDgzMCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.ETEXJdw9HPrs_Tq46R5h09f7HzxiY7DlzcRDpGdiDCrhFgdxiC55ix55DwhiV6N4P6GpFtC7Ujc0c9MlmOoS1oikO0dRLiaBlCztbVTQRdgvHvga1K89qG85dmfh_6RWjIv77hL03XmYQ70MSXXdemIqewrpLpkzqjfZYi7DKCMjL_p6kBit62BfkcpCj7KFfEvHs1-nkQxFmZIW24LrUcxBXG0fasWTJ4vmTVkE8XNf9a2TdnP5DfhWx2p7OFmxNEfkAR8qEnrGvXyEyIdrRiK4mksfOt3utGPNH454z_Mh3SDYTjaJr9IZbp81UeuAEPLwfNRgeWTRlj5DO2r27w"

// Request Structure
type BaseConfig struct {
	Algo string `json:"algo"`
	Kms  string `json:"kms"`
	Flow string `json:"flow"`
}
type GenerateKeyRequest BaseConfig

type KeySignRequest struct {
	BaseConfig `json:"base_config"`
	PrivateKey string `json:"priv"`
	DigestData string `json:"digest"`
}

type KeyVerifyRequest struct {
	BaseConfig `json:"base_config"`
	PublicKey  string `json:"pub"`
	DigestData string `json:"digest"`
	Signature  string `json:"signature"`
}

type SignwithoutKeyRequest struct {
	BaseConfig `json:"base_config"`
	DigestData string `json:"digest"`
	IDToken    string `json:"id_token"`
	SignMgr    string `json:"sign_mgr"`
	SignMgrUrl string `json:"sign_mgr_url"`
	CertMgr    string `json:"cert_mgr"`
	CertMgrUrl string `json:"cert_mgr_url"`
}

type KeylessVerifyRequest struct {
	BaseConfig `json:"base_config"`
	Digest     string      `json:"digest"`
	Signature  string      `json:"signature"`
	Cert       Certificate `json:"cert"`
	CertIssuer string      `json:"cert_issuer"`
	CertSAN    string      `json:"cert_san"`
	SignMgr    string      `json:"sign_mgr"`
	SignMgrUrl string      `json:"sign_mgr_url"`
	CertMgr    string      `json:"cert_mgr"`
	CertMgrUrl string      `json:"cert_mgr_url"`
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

type VerifyResponse struct {
	BaseConfig `json:"base_config"`
	Result     string `json:"result"`
}

// TODO: VERIFY BY TRUE RESPONSE
type SignwithoutKeyResponse struct {
	BaseConfig `json:"base_config"`
	Signature  string      `json:"signature"`
	Cert       Certificate `json:"cert"`
}
type Certificate struct {
	CertPEM       string `json:"CertPEM"`
	ChainPEM      string `json:"ChainPEM"`
	SCT           string `json:"SCT"`
	Identity      string `json:"Identity"`
	Subject       string `json:"Subject"`
	SubjectRegExp string `json:"SubjectRegExp"`
	Issuer        string `json:"Issuer"`
	IssuerRegExp  string `json:"IssuerRegExp"`
	Token         string `json:"Token"`
}
type KeylessVerifyResponse VerifyResponse

func main() {

	http.HandleFunc("/generateKey", keyGenerationHandler)
	http.HandleFunc("/signwithKey", signwithKeyHandler)
	http.HandleFunc("/verifywithKey", verifywithKeyHandler)
	http.HandleFunc("/signwithoutKey", signwithoutKeyHandler)
	http.HandleFunc("/verifywithoutKey", verifywithoutKeyHandler)

	log.Println("Key Generation Proxy started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func verifywithoutKeyHandler(w http.ResponseWriter, r *http.Request) {
	/*
		1. jump-server check
		2. send request
			2.1 generate client
			2.2 request struct
			2.3 struct to json
			2.4 request header set
			2.5 send request
		3. receive response
			3.1 read response
			2.3 parse response
		4. jump server return
	*/
	if r.Method != http.MethodGet {
		http.Error(w, "Only Get method allow: %v", http.StatusMethodNotAllowed)
		return
	}

	var keylessVerifyRequest KeylessVerifyRequest
	keylessVerifyRequest = KeylessVerifyRequest{
		BaseConfig: BaseConfig{
			Algo: "ecdsa",
			Kms:  "",
			Flow: "classic",
		},
		Signature: CommonSignature,
		Cert:      CommonCertificate,
	}

	body, err := json.Marshal(keylessVerifyRequest)
	if err != nil {
		log.Printf("request data failed: %v", err)
		http.Error(w, "generate request failed", http.StatusInternalServerError)
		return
	}

	url := "https://10.20.173.8:18081/v1/verify/digest"

	client := http.Client{Timeout: 5 * time.Second}

	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("request failed: %v", err)
		http.Error(w, "generate request failed", http.StatusInternalServerError)
	}

	request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		log.Printf("http request failed: %v", err)
		http.Error(w, "http request failed", http.StatusInternalServerError)
		return
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("http request failed: %v", err)
		http.Error(w, "http request failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var vr VerifyResponse
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		log.Printf("http request failed: %v", err)
		http.Error(w, "http request failed", http.StatusInternalServerError)
		return
	}

	log.Printf("Backend API response - Status: %d, Body: %s", string(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func signwithoutKeyHandler(w http.ResponseWriter, r *http.Request) {
	// check if the request received from client is standard
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET Method Is Allowed", http.StatusMethodNotAllowed)
		return
	}

	// generate request
	// generate client
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	// construct request to signatom server
	signwithoutKeyRequest := SignwithoutKeyRequest{
		BaseConfig: BaseConfig{
			Algo: "ecdsa",
			Flow: "classic",
		},
		DigestData: DIGEST,

		//TODO: How to Get ID Token? Generate another ID Token Service
		IDToken:    IDTOKEN,
		SignMgr:    "rekor",
		SignMgrUrl: "http://rekor.rekor-system.svc:18080",
		CertMgr:    "fulcio",
		CertMgrUrl: "http://fulcio.fulcio-system.svc:18080",
	}
	// tranform requestData to json
	requestBody, err := json.Marshal(signwithoutKeyRequest)
	if err != nil {
		log.Printf("construct request data failed: %v\n", err)
		http.Error(w, "construct request data failed\n", http.StatusInternalServerError)
		return
	}
	url := "http://10.20.173.8:18081/v1/sign/digest"
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		log.Printf("generate http request failed: %v\n", err)
		http.Error(w, "construct request data failed\n", http.StatusInternalServerError)
	}
	request.Header.Set("Content-Type", "application/json")

	// send request
	resp, err := client.Do(request)

	// read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("read response failed: %v\n", err)
		http.Error(w, "Read response failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// parse reponse
	var sr SignwithoutKeyResponse
	err = json.Unmarshal(responseBody, &sr)
	if err != nil {
		log.Printf("parse reponse failed: %v\n", err)
		http.Error(w, "Parse response failed", http.StatusInternalServerError)
		return
	}
	CommonCertificate = sr.Cert
	CommonSignature = sr.Signature

	log.Printf("Backend API response - Status: %d, Body: %v", resp.StatusCode, sr)

	// return the response to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(responseBody)

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
	keyVerifyRequest := KeyVerifyRequest{
		BaseConfig: BaseConfig{
			Algo: "sm2",
			Kms:  "",
			Flow: "classic",
		},
		PublicKey:  CommonPublicKey,
		DigestData: DIGEST,
		Signature:  CommonSignature,
	}

	reqBody, err := json.Marshal(keyVerifyRequest)
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

	var vr VerifyResponse
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
	keySignRequest := KeySignRequest{
		BaseConfig: BaseConfig{
			Algo: "sm2",
			Kms:  "", // Empty string
			Flow: "classic",
		},
		PrivateKey: CommonPrivateKey,
		DigestData: DIGEST, // Replace with actual digest data
	}

	// Convert to JSON
	reqBody, err := json.Marshal(keySignRequest)
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
