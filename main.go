package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			// 1. Cast the public key to an SSH Certificate
			fmt.Println("Starting PublicKeyCallback verification...")
			cert, ok := pubKey.(*ssh.Certificate)
			if !ok {
				return nil, fmt.Errorf("client did not provide an SSH certificate (plain public key rejected)")
			}

			for extName, extValue := range cert.Extensions {
				fmt.Printf("Certificate Extension: %s = %s\n", extName, extValue)
			}

			// 2. Extract the Base64 x509 data from the custom extension
			fmt.Println("Extracting x509 extension from SSH certificate...")
			x509Base64, exists := cert.Extensions["x509-auth-data@yourdomain.com"]
			if !exists {
				return nil, fmt.Errorf("certificate missing required x509 extension")
			}

			// 3. Decode the x509 DER from Base64
			fmt.Println("Decoding x509 extension...")
			derBytes, err := base64.StdEncoding.DecodeString(x509Base64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode x509 extension: %v", err)
			}

			// 4. Parse the x509 Certificate
			fmt.Println("Parsing x509 certificate...")
			x509Cert, err := x509.ParseCertificate(derBytes)
			if err != nil {
				return nil, fmt.Errorf("invalid x509 certificate data: %v", err)
			}

			// 5. EXTENDED CRYPTOGRAPHIC CROSS-CHECK
			// Ensure the public key inside the x509 cert matches the key inside the SSH cert
			fmt.Println("Performing cryptographic cross-check between SSH cert and x509 cert public keys...")
			x509sshPubKey, err := ssh.NewPublicKey(x509Cert.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to convert x509 public key to ssh format: %v", err)
			}

			// cert.Key is the underlying public key of the SSH certificate
			if !bytes.Equal(cert.Key.Marshal(), x509sshPubKey.Marshal()) {
				return nil, fmt.Errorf("cryptographic mismatch: SSH certificate key does not match x509 public key")
			}

			// 6. IDENTITY VALIDATION
			// Ensure the ID in the x509 Common Name matches the SSH username provided
			fmt.Println("Validating identity match between x509 CN and SSH user...")
			if x509Cert.Subject.CommonName != conn.User() {
				return nil, fmt.Errorf("identity mismatch: x509 CN '%s' does not match SSH user '%s'", x509Cert.Subject.CommonName, conn.User())
			}

			// 7. Check Revocation (e.g., OCSP/CRL)
			// This is where you call your PKI to ensure x509Cert is still valid
			// if isRevoked(x509Cert) {
			// 	return nil, fmt.Errorf("x509 certificate has been revoked")
			// }

			fmt.Printf("Authenticated %s via x509 Serial: %s\n", conn.User(), hex.EncodeToString(x509Cert.SerialNumber.Bytes()))

			return &ssh.Permissions{
				Extensions: map[string]string{
					"x509-serial": hex.EncodeToString(x509Cert.SerialNumber.Bytes()),
					"common-name": x509Cert.Subject.CommonName,
				},
			}, nil
		},
	}

	privateBytes, err := os.ReadFile("server_key")
	if err != nil {
		log.Fatal("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection: %v", err)
			continue
		}

		// Handle each connection in its own goroutine
		go handleConnection(nConn, config)
	}
}

func handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("handshake failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("Logged in: %s (x509: %s)", conn.User(), conn.Permissions.Extensions["x509-serial"])

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			return
		}

		// Forward the session to the backend
		handleSession(channel, requests, conn)
	}
}

func handleSession(clientChannel ssh.Channel, clientRequests <-chan *ssh.Request, clientConn *ssh.ServerConn) {
	defer clientChannel.Close()

	// --- BACKEND AUTHENTICATION SETUP ---
	// In this example, the proxy uses its own key to log into the backend.
	// Ensure this key is in the 'authorized_keys' of the backend machine.
	proxyKeyBytes, err := os.ReadFile("/home/ubuntu/.ssh/id_ed25519") // Usually a dedicated proxy identity key
	if err != nil {
		log.Printf("Proxy identity key not found: %v", err)
		return
	}
	signer, err := ssh.ParsePrivateKey(proxyKeyBytes)
	if err != nil {
		log.Printf("Failed to parse proxy key: %v", err)
		return
	}

	backendAddress := "127.0.0.1:22" // Update with your real backend IP
	backendConfig := &ssh.ClientConfig{
		User: "ubuntu", // Forward the username requested by client
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Use ssh.FixedHostKey in production
	}

	backendConn, err := ssh.Dial("tcp", backendAddress, backendConfig)
	if err != nil {
		log.Printf("Backend connection failed: %v", err)
		return
	}
	defer backendConn.Close()

	backendChannel, backendRequests, err := backendConn.OpenChannel("session", nil)
	if err != nil {
		log.Printf("Backend channel failed: %v", err)
		return
	}
	defer backendChannel.Close()

	// --- RELAY LOGIC ---
	var wg sync.WaitGroup
	wg.Add(2)

	// 4. Relay Requests (PTY, Shell, Window Changes, etc.)
	go func() {
		for req := range clientRequests {
			// FIXED: SendRequest returns (bool, error)
			ok, err := backendChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("Error sending request to backend: %v", err)
				continue
			}
			if req.WantReply {
				req.Reply(ok, nil)
			}
		}
	}()

	go func() {
		for req := range backendRequests {
			// FIXED: SendRequest returns (bool, error)
			ok, err := clientChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("Error sending request to client: %v", err)
				continue
			}
			if req.WantReply {
				req.Reply(ok, nil)
			}
		}
	}()

	// Bidirectional data pipe
	go func() {
		defer wg.Done()
		io.Copy(clientChannel, backendChannel)
	}()
	go func() {
		defer wg.Done()
		io.Copy(backendChannel, clientChannel)
	}()

	wg.Wait()
}

func FetchCertificate(clientID string) (*x509.Certificate, error) {
	cert := `-----BEGIN CERTIFICATE-----
MIID3jCCAsagAwIBAgIRAI4AOh+VoB+aw2tgLX5pk3YwDQYJKoZIhvcNAQELBQAw
DzENMAsGA1UEAxMEUm9vdDAeFw0yNjAxMjkyMDE3NDhaFw0zMTAxMjMyMDE3NDha
MBAxDjAMBgNVBAMTBWRldi0xMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA3hpmM3213iveZj36Jszncp/JCmEmA29Fxaurkkc+tgN4bxS6+YdJMmN64WD0
crK7oYeQjoJBNfOppZOAKTBMbmj5Ekr4me1Jis2J5tLyLSBrf76QaFh7wAhiSCtn
MXRwIPYOMv7SmQJ5VAetkxdT4NXL5FtHKjDdNNS0DfejP8Uyv29PwN3beGoETR88
ipcVbdF1r8zQv70whSvPFxKJeCQPlQJJfOWtgXBruDJRA3cUuhLBIatwefuygc8P
5AGHsv9NWGg7jZnLRnlUKZHNTwX6h55eMEcIpVfjgfAFTvgxCQfvd+/YWTZE9HuK
Yj4mzyGlOD/NKhxCPwNQQewAqQIDAQABo4IBMjCCAS4wDgYDVR0PAQH/BAQDAgWg
MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATApBgNVHQ4EIgQgUyyh0iqo
dC58q4xYQOheiRZLvBhYq/zZC3deAzTBBtAwKwYDVR0jBCQwIoAg1x2f+7kmDUU9
3NvdVPT8qVR4VFAMsf/ghZC9pCvm8+QwNwYIKwYBBQUHAQEEKzApMCcGCCsGAQUF
BzABhhtodHRwOi8vcGtpLmhsYWIvYXBpL3ZhL29jc3AwbAYDVR0fBGUwYzBhoF+g
XYZbaHR0cDovL3BraS5obGFiL2FwaS92YS9jcmwvZDcxZDlmZmJiOTI2MGQ0NTNk
ZGNkYmRkNTRmNGZjYTk1NDc4NTQ1MDBjYjFmZmUwODU5MGJkYTQyYmU2ZjNlNDAN
BgkqhkiG9w0BAQsFAAOCAQEAAXNMNMKUQNPl9Fw9M36Zf9cg3690F9QLSDydNH4w
e3b5+wUT5aux+oz1j/3JSTYUCDD15biNxN74OI/AbcrZFShD6JT2TBgxt+gWH/xq
1IVa9KrLbjB+xzGvciciipfhqxgLOhmANIO2FLKOWRjgrdJIsOGVayK6zS0KGFv+
GdGZb+mOeoxshT9U+D7OzFF1zMxwrw1vXYwEpEOaYlGlbpI5brTL79+dv6p1uVPG
XHY4ddx2IOBndYBwxE3mxxgcQEHT7BLRa+ReKbUJVi2GGboGAG0hp5PseLFxaY42
GYGwvSlkHSx26rjI//oL/dvML6FAXb0YErTIuR10zaUS9w==
-----END CERTIFICATE-----
`
	pemBlock, _ := pem.Decode([]byte(cert))
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	x509Cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return x509Cert, nil
}
