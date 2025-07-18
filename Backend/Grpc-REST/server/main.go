package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/credentials"

	"grpc-crypto/grpc-crypto/proto"
	pb "grpc-crypto/grpc-crypto/proto"

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedCryptoServiceServer
}

//AES

func (s *server) EncryptAES(ctx context.Context, req *pb.AESCryptoRequest) (*pb.CryptoResponse, error) {
	key := []byte(req.Key)
	data := []byte(req.Data)

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid AES key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil) // nonce is prepended
	return &pb.CryptoResponse{Result: hex.EncodeToString(ciphertext)}, nil
}

// decrytpion of aes
func (s *server) DecryptAES(ctx context.Context, req *pb.AESCryptoRequest) (*pb.CryptoResponse, error) {
	key := []byte(req.Key)
	data, err := hex.DecodeString(req.Data)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return &pb.CryptoResponse{Result: string(plaintext)}, nil
}

// des implementation

func (s *server) EncryptDES(ctx context.Context, req *pb.DESCryptoRequest) (*pb.CryptoResponse, error) {
	key := []byte(req.Key)
	data := []byte(req.Data)

	if len(key) != 8 {
		return nil, errors.New("DES key must be of 8 bytes")
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, des.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(data))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, data)

	final := append(iv, ciphertext...)
	return &pb.CryptoResponse{Result: hex.EncodeToString(final)}, nil
}

//des decryption

func (s *server) DecryptDES(ctx context.Context, req *pb.DESCryptoRequest) (*pb.CryptoResponse, error) {
	key := []byte(req.Key)
	encrypteddata, err := hex.DecodeString(req.Data)
	if err != nil {
		return nil, err
	}
	if len(encrypteddata) < des.BlockSize {
		return nil, errors.New("cipher text too small")
	}

	iv := encrypteddata[:des.BlockSize]
	ciphertext := encrypteddata[des.BlockSize:]

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return &pb.CryptoResponse{Result: string(plaintext)}, nil
}

// implementing sha
func (s *server) HashSHA256(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	hash := sha256.Sum256([]byte(req.Data))
	return &pb.HashResponse{Hash: hex.EncodeToString(hash[:])}, nil
}

// implementing rsa
func (s *server) EncryptRSA(ctx context.Context, req *pb.RSACryptoRequest) (*pb.CryptoResponse, error) {
	block, _ := pem.Decode([]byte(req.PublicKey))
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}

	pubKeyIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey := pubKeyIface.(*rsa.PublicKey)

	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, []byte(req.Data), nil)
	if err != nil {
		return nil, err
	}

	return &pb.CryptoResponse{Result: base64.StdEncoding.EncodeToString(encrypted)}, nil
}

// decrypt rsa
func (s *server) DecryptRSA(ctx context.Context, req *pb.RSACryptoRequest) (*pb.CryptoResponse, error) {
	block, _ := pem.Decode([]byte(req.PrivateKey))
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}

	privkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPrivKey, ok := privkey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return nil, err
	}

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivKey, cipherBytes, nil)
	if err != nil {
		return nil, err
	}

	return &pb.CryptoResponse{Result: string(decrypted)}, nil
}

func allowCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // Or use "http://localhost:3000"
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func main() {
	// Load TLS credentials
	creds, err := credentials.NewServerTLSFromFile("certs/server.crt", "certs/server.key")
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	// Start gRPC server with TLSAC
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	proto.RegisterCryptoServiceServer(grpcServer, &server{})

	go func() {
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		log.Println("gRPC server listening on port 50051 with TLS")
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	// Setup REST gateway (gRPC-Gateway)
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()

	// Create TLS credentials for gRPC client
	tlsCreds, _ := credentials.NewClientTLSFromFile("certs/server.crt", "")
	opts := []grpc.DialOption{grpc.WithTransportCredentials(tlsCreds)}

	// Register handler
	err = proto.RegisterCryptoServiceHandlerFromEndpoint(ctx, mux, "localhost:50051", opts)
	if err != nil {
		log.Fatalf("Failed to start gRPC-Gateway: %v", err)
	}

	// Serve REST on port 8080
	log.Println("REST Gateway listening on port 8080 with TLS")
	if err := http.ListenAndServeTLS(":8080", "certs/server.crt", "certs/server.key", allowCORS(mux)); err != nil {
		log.Fatalf("Failed to serve REST: %v", err)
	}
}
