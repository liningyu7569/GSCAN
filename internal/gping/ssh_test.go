package gping

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunSSHBasicConfirmAddsClaimsAndRecommendation(t *testing.T) {
	listener, expectedFingerprint := startFakeSSHServer(t)
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	result, err := Run(context.Background(), Options{
		Commandline:  "goscan gping --ip 127.0.0.1 --port test --template uam/ssh-enrich",
		IP:           "127.0.0.1",
		Port:         port,
		TemplateName: "uam/ssh-enrich",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Reports) != 3 {
		t.Fatalf("unexpected report count: got %d want 3", len(result.Reports))
	}
	if !hasClaim(result.Reports[0], "service", "name", "ssh") {
		t.Fatalf("expected service.name=ssh claim, got %+v", result.Reports[0].Claims)
	}
	if !hasClaim(result.Reports[0], "ssh", "software_version", "OpenSSH_9.6") {
		t.Fatalf("expected ssh.software_version claim, got %+v", result.Reports[0].Claims)
	}
	if !hasJSONClaim(result.Reports[1], "ssh", "kex_algorithms") {
		t.Fatalf("expected ssh.kex_algorithms JSON claim, got %+v", result.Reports[1].Claims)
	}
	if !hasClaim(result.Reports[2], "ssh", "hostkey_fingerprint", expectedFingerprint) {
		t.Fatalf("expected ssh.hostkey_fingerprint claim, got %+v", result.Reports[2].Claims)
	}
	if !hasJSONClaim(result.Reports[1], "ssh", "ciphers") {
		t.Fatalf("expected ssh.ciphers extract claim, got %+v", result.Reports[1].Claims)
	}
	if len(result.Recommendations) != 1 || result.Recommendations[0].VerificationState != "pending" {
		t.Fatalf("unexpected recommendations: %+v", result.Recommendations)
	}
}

func startFakeSSHServer(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey returned error: %v", err)
	}
	hostKeyBlob := buildFakeSSHHostKeyBlob(privateKey.Public().(ed25519.PublicKey))
	sum := sha256.Sum256(hostKeyBlob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(conn)
				io.WriteString(conn, "SSH-2.0-OpenSSH_9.6\r\n")
				clientBanner, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if !strings.HasPrefix(strings.TrimSpace(clientBanner), "SSH-") {
					return
				}
				if err := writeSSHPacket(conn, buildFakeServerSSHKexInitPacket()); err != nil {
					return
				}

				firstPacket, err := readSSHPacket(reader)
				if err != nil || len(firstPacket) == 0 {
					return
				}
				if firstPacket[0] != sshMessageKexInit {
					return
				}
				secondPacket, err := readSSHPacket(reader)
				if err != nil || len(secondPacket) == 0 {
					return
				}
				if secondPacket[0] != sshMessageKexECDHInit {
					return
				}
				reply, err := buildFakeSSHECDHReplyPacket(hostKeyBlob, privateKey)
				if err != nil {
					return
				}
				_ = writeSSHPacket(conn, reply)
			}(conn)
		}
	}()

	return listener, fingerprint
}

func buildFakeServerSSHKexInitPacket() []byte {
	payload := make([]byte, 0, 512)
	payload = append(payload, sshMessageKexInit)
	payload = append(payload, make([]byte, 16)...)
	payload = appendSSHNameList(payload, []string{"ecdh-sha2-nistp256", "curve25519-sha256"})
	payload = appendSSHNameList(payload, []string{"ssh-ed25519", "rsa-sha2-512"})
	payload = appendSSHNameList(payload, []string{"aes128-ctr", "aes256-ctr"})
	payload = appendSSHNameList(payload, []string{"aes128-ctr", "aes256-ctr"})
	payload = appendSSHNameList(payload, []string{"hmac-sha2-256", "hmac-sha1"})
	payload = appendSSHNameList(payload, []string{"hmac-sha2-256", "hmac-sha1"})
	payload = appendSSHNameList(payload, []string{"none"})
	payload = appendSSHNameList(payload, []string{"none"})
	payload = appendSSHNameList(payload, nil)
	payload = appendSSHNameList(payload, nil)
	payload = append(payload, 0x00)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)
	return payload
}

func buildFakeSSHHostKeyBlob(publicKey ed25519.PublicKey) []byte {
	payload := []byte{}
	payload = appendSSHString(payload, []byte("ssh-ed25519"))
	payload = appendSSHString(payload, publicKey)
	return payload
}

func buildFakeSSHECDHReplyPacket(hostKeyBlob []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverPublic := elliptic.Marshal(serverKey.Curve, serverKey.PublicKey.X, serverKey.PublicKey.Y)
	signatureBytes := ed25519.Sign(privateKey, []byte("gping-fake-signature"))
	signatureBlob := []byte{}
	signatureBlob = appendSSHString(signatureBlob, []byte("ssh-ed25519"))
	signatureBlob = appendSSHString(signatureBlob, signatureBytes)

	payload := []byte{sshMessageKexECDHReply}
	payload = appendSSHString(payload, hostKeyBlob)
	payload = appendSSHString(payload, serverPublic)
	payload = appendSSHString(payload, signatureBlob)
	return payload, nil
}
