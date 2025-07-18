package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	pb "grpc-crypto/grpc-crypto/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	// Load TLS credentials (ensure server.crt exists and is valid)
	creds, err := credentials.NewClientTLSFromFile("certs/server.crt", "")
	if err != nil {
		log.Fatalf("Failed to load TLS cert: %v", err)
	}

	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewCryptoServiceClient(conn)

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== Crypto Client ===")
	fmt.Println("Choose an operation:")
	fmt.Println("1: AES Encrypt")
	fmt.Println("2: AES Decrypt")
	fmt.Println("3: DES Encrypt")
	fmt.Println("4: DES Decrypt")
	fmt.Println("5: SHA-256 Hash")
	fmt.Println("6: RSA Encrypt")
	fmt.Println("7: RSA Decrypt")

	fmt.Print("Enter choice (1-7): ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	switch choice {
	case "1", "2":
		fmt.Print("Enter AES key (base64 encoded, 16/24/32 bytes): ")
		key, _ := reader.ReadString('\n')
		fmt.Print("Enter the data: ")
		data, _ := reader.ReadString('\n')

		req := &pb.AESCryptoRequest{
			Key:  strings.TrimSpace(key),
			Data: strings.TrimSpace(data),
		}

		if choice == "1" {
			resp, err := client.EncryptAES(ctx, req)
			handleresponse("AES Encrypted", resp, err)
		} else {
			resp, err := client.DecryptAES(ctx, req)
			handleresponse("AES Decrypted", resp, err)
		}
	case "3", "4":
		fmt.Print("Enter the DES key: ")
		key, _ := reader.ReadString('\n')
		fmt.Print("Enter the data: ")
		data, _ := reader.ReadString('\n')

		req := &pb.DESCryptoRequest{
			Key:  strings.TrimSpace(key),
			Data: strings.TrimSpace(data),
		}

		if choice == "3" {
			resp, err := client.EncryptDES(ctx, req)
			handleresponse("DES Encrypted", resp, err)
		} else {
			resp, err := client.DecryptDES(ctx, req)
			handleresponse("DES Decrypted", resp, err)
		}
	case "5":
		fmt.Print("Enter data to hash: ")
		data, _ := reader.ReadString('\n')
		resp, err := client.HashSHA256(ctx, &pb.HashRequest{
			Data: strings.TrimSpace(data),
		})
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			fmt.Println("SHA-256 Hash:", resp.Hash)
		}
	case "6":
		fmt.Print("Enter the Public key (PEM FORMAT):\n")
		publicKey, _ := readMultilineInput()
		fmt.Print("Enter the data: ")
		data, _ := reader.ReadString('\n')

		resp, err := client.EncryptRSA(ctx, &pb.RSACryptoRequest{
			Data:      strings.TrimSpace(data),
			PublicKey: publicKey,
		})
		handleresponse("RSA Encrypted", resp, err)

	case "7":
		fmt.Print("Enter the Private key (PEM FORMAT):\n")
		privateKey, _ := readMultilineInput()
		fmt.Print("Enter the Encrypted data: ")
		data, _ := reader.ReadString('\n')

		resp, err := client.DecryptRSA(ctx, &pb.RSACryptoRequest{
			Data:       strings.TrimSpace(data),
			PrivateKey: privateKey,
		})
		handleresponse("RSA Decrypted", resp, err)

	default:
		fmt.Println("Invalid choice")
	}
}

func handleresponse(label string, resp *pb.CryptoResponse, err error) {
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("%s: %s\n", label, resp.Result)
	}
}

func readMultilineInput() (string, error) {
	fmt.Println("Paste your key below. End input with a single line: END")
	reader := bufio.NewScanner(os.Stdin)
	var lines []string
	for reader.Scan() {
		line := reader.Text()
		if strings.TrimSpace(line) == "END" {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"), nil
}
