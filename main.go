package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

// 目标API的请求结构（固定参数）
type TargetRequest struct {
	Algo string `json:"algo"`
	Kms  string `json:"kms"`
	Flow string `json:"flow"`
}

// 目标API的响应结构（示例，根据实际情况调整）
type TargetResponse struct {
	Algo     string `json:"algo"`
	Flow     string `json:"flow"`
	KeyPair  string `json:"key_pair"`
	ErrorMsg string `json:"error,omitempty"`
}

func main() {
	// 设置路由
	http.HandleFunc("/generateKey", keyGenerationHandler)

	log.Println("Key Generation Proxy started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func keyGenerationHandler(w http.ResponseWriter, r *http.Request) {
	// 只允许GET方法
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// 构造固定参数的请求体
	targetReq := TargetRequest{
		Algo: "sm2",
		Kms:  "", // 空字符串
		Flow: "classic",
	}

	// 转换为JSON
	reqBody, err := json.Marshal(targetReq)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 创建带超时的HTTP客户端（5秒超时）
	client := &http.Client{Timeout: 5 * time.Second}

	// 创建目标API请求
	targetURL := "http://10.20.173.8:80/v1/keypair"
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("Request creation error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "KeyGenerationProxy/1.0")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("API request failed: %v", err)
		http.Error(w, "Backend service unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Response read error: %v", err)
		http.Error(w, "Error reading backend response", http.StatusInternalServerError)
		return
	}

	// 记录响应状态（调试用）
	log.Printf("Backend API response - Status: %d, Body: %s", resp.StatusCode, string(body))

	// 将目标API的响应状态码和内容原样返回给客户端
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}
