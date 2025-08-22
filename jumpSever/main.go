package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

type rGenerateKey BaseConfig

// Request Key Sign
type rKeySign struct {
	BaseConfig `json:"base_config"`
	PrivateKey string `json:"priv"`
	DigestData string `json:"digest"`
}

type rKeyVerify struct {
	BaseConfig `json:"base_config"`
	PublicKey  string `json:"pub"`
	DigestData string `json:"digest"`
	Signature  string `json:"signature"`
}

type rKeylessSign struct {
	BaseConfig `json:"base_config"`
	DigestData string `json:"digest"`
	IDToken    string `json:"id_token"`
	SignMgr    string `json:"sign_mgr"`
	SignMgrUrl string `json:"sign_mgr_url"`
	CertMgr    string `json:"cert_mgr"`
	CertMgrUrl string `json:"cert_mgr_url"`
}

type rKeylessVerify struct {
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
type rsGenerateKey struct {
	BaseConfig `json:"base_conig"`
	PrivateKey string `json:"priv"`
	PublicKey  string `json:"pub"`
	KeyId      string `json:"key_id"`
}

type rsKeySign struct {
	BaseConfig `json:"base_config"`
	Signature  string `json:"signature"`
	Cert       string `json:"cert"`
}

type rsVerify struct {
	BaseConfig `json:"base_config"`
	Result     string `json:"result"`
}

// TODO: VERIFY BY TRUE RESPONSE
type rsKeylessSign struct {
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
type rsKeylessVerify rsVerify

func main() {

	http.HandleFunc("/generateKey", keyGenerationHandler)
	http.HandleFunc("/signwithKey", keySignHandler)
	http.HandleFunc("/verifywithKey", keyVerifyHandler)
	http.HandleFunc("/signwithoutKey", keylessSignHandler)
	http.HandleFunc("/verifywithoutKey", keylessVerifyHandler)

	log.Println("Key Generation Proxy started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func keylessVerifyHandler(w http.ResponseWriter, r *http.Request) {

	checkReceivedMethod(w, r)

	rklv := rKeylessVerify{
		BaseConfig: BaseConfig{
			Algo: "ecdsa",
			Kms:  "",
			Flow: "classic",
		},
		Signature: CommonSignature,
		Cert:      CommonCertificate,
	}

	url := "https://10.20.173.8:18081/v1/verify/digest"

	rsbody, statusCode, err := makeRequest(&w, rklv, url)
	if err != nil {
		log.Printf("%v", err)
		return
	}

	var vr rsVerify
	err = json.Unmarshal(rsbody, &vr)
	if err != nil {
		log.Printf("http request failed: %v", err)
		http.Error(w, "http request failed", http.StatusInternalServerError)
		return
	}

	log.Printf("Backend API response - Status: %d, Body: %v", statusCode, vr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(rsbody)
}

func keylessSignHandler(w http.ResponseWriter, r *http.Request) {
	checkReceivedMethod(w, r)

	rkls := rKeylessSign{
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

	url := "http://10.20.173.8:18081/v1/sign/digest"
	rsbody, statusCode, err := makeRequest(&w, rkls, url)
	if err != nil {
		log.Printf("%v", err)
	}

	var rskls rsKeylessSign
	err = json.Unmarshal(rsbody, &rskls)
	if err != nil {
		log.Printf("parse reponse failed: %v\n", err)
		http.Error(w, "Parse response failed", http.StatusInternalServerError)
		return
	}
	CommonCertificate = rskls.Cert
	CommonSignature = rskls.Signature

	log.Printf("Backend API response - Status: %d, Body: %v", statusCode, rskls)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(rsbody)
}

func keyVerifyHandler(w http.ResponseWriter, r *http.Request) {
	checkReceivedMethod(w, r)

	if len(CommonSignature) == 0 || len(CommonPublicKey) == 0 || len(DIGEST) == 0 {
		http.Error(w, "signature or public key or digest is not set", http.StatusInternalServerError)
		return
	}

	rkv := rKeyVerify{
		BaseConfig: BaseConfig{
			Algo: "sm2",
			Kms:  "",
			Flow: "classic",
		},
		PublicKey:  CommonPublicKey,
		DigestData: DIGEST,
		Signature:  CommonSignature,
	}

	url := "http://10.20.173.8:80/v1/verify/digest"
	rsbody, statusCode, err := makeRequest(&w, rkv, url)
	if err != nil {
		return
	}

	var vr rsVerify
	err = json.Unmarshal(rsbody, &vr)
	if err != nil {
		log.Printf("Response parse error: %v", err)
		http.Error(w, "Error parsing backend response", http.StatusInternalServerError)
		return
	}

	log.Printf("Backend API response - Status: %d, Body: %v", statusCode, vr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(rsbody)
}

func keySignHandler(w http.ResponseWriter, r *http.Request) {
	checkReceivedMethod(w, r)

	// check common private key
	if CommonPrivateKey == "" {
		http.Error(w, "Common private key is not set", http.StatusInternalServerError)
		return
	}

	rks := rKeySign{
		BaseConfig: BaseConfig{
			Algo: "sm2",
			Kms:  "", // Empty string
			Flow: "classic",
		},
		PrivateKey: CommonPrivateKey,
		DigestData: DIGEST, // Replace with actual digest data
	}

	url := "http://10.20.173.8:80/v1/sign/digest"

	rsbody, statusCode, err := makeRequest(&w, rks, url)
	if err != nil {
		log.Printf("%v", err)
		return
	}

	var resks rsKeySign
	err = json.Unmarshal(rsbody, &resks)
	if err != nil {
		log.Printf("Response parse error: %v", err)
		http.Error(w, "Error reading backend response", http.StatusInternalServerError)
		return
	}

	CommonSignature = resks.Signature

	log.Printf("Backend API response - Status: %d, Body: %v", statusCode, resks)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(rsbody)
}

func keyGenerationHandler(w http.ResponseWriter, r *http.Request) {
	checkReceivedMethod(w, r)

	rgk := rGenerateKey{
		Algo: "sm2",
		Kms:  "",
		Flow: "classic",
	}

	url := "http://10.20.173.8:80/v1/keypair"
	rsbody, statusCode, err := makeRequest(&w, rgk, url)
	if err != nil {
		log.Printf("%v", err)
		return
	}

	var resgk rsGenerateKey
	err = json.Unmarshal(rsbody, &resgk)
	if err != nil {
		log.Printf("Response parse error: %v", err)
		http.Error(w, "Error parsing backend response", http.StatusInternalServerError)
		return
	}

	CommonPrivateKey = resgk.PrivateKey
	CommonPublicKey = resgk.PublicKey

	log.Printf("Backend API response - Status: %d, Body: %v", statusCode, resgk)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(rsbody)
}

func checkReceivedMethod(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}
}

func makeRequest(w *http.ResponseWriter, r any, url string) (responseBody []byte, statusCode int, err error) {
	rbody, err := json.Marshal(r)
	if err != nil {
		http.Error(*w, "marshal request body failed", http.StatusBadRequest)
		return nil, http.StatusNotImplemented, fmt.Errorf("marshal request body failed: %v", err)
	}

	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(rbody))
	if err != nil {
		http.Error(*w, "create request failed", http.StatusInternalServerError)
		return nil, http.StatusNotImplemented, fmt.Errorf("create request failed: %v", err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Signatom/1.0")

	client := http.Client{
		Timeout: 5 * time.Second,
	}

	response, err := client.Do(request)
	if err != nil {
		http.Error(*w, "Backend service unavailable", http.StatusBadGateway)
		return nil, http.StatusNotImplemented, fmt.Errorf("send an HTTP request failed: %v", err)
	}

	rsbody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, http.StatusNotImplemented, fmt.Errorf("read response failed: %v", err)
	}
	defer response.Body.Close()

	return rsbody, response.StatusCode, nil
}
