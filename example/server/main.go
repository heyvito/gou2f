package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/heyvito/gou2f/example/rpc"
	"github.com/heyvito/gou2f/fido"
	"github.com/heyvito/gou2f/sec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"log"
	"net"
)

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", 9090))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	opts = append(opts, grpc.Creds(insecure.NewCredentials()))
	grpcServer := grpc.NewServer(opts...)
	rpc.RegisterExampleServer(grpcServer, newExampleServer())
	grpcServer.Serve(lis)
}

type ExServer struct {
	rpc.UnimplementedExampleServer
}

func newExampleServer() rpc.ExampleServer {
	return &ExServer{}
}

// Place your registration data below
var registrationData = ""

func (ExServer) Authenticate(_ context.Context, rad *rpc.AuthorizationData) (*rpc.AuthorizationResult, error) {
	d, err := hex.DecodeString(registrationData)
	if err != nil {
		return nil, err
	}
	r, err := fido.ParseRegisterAttestation(d)
	if err != nil {
		return nil, err
	}

	ad, err := r.AuthenticatorData()
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(ad.AttestedCredentialData.CredentialID, rad.CredentialID) {
		return nil, status.Error(codes.PermissionDenied, "Invalid CredentialID")
	}

	authData, err := fido.ParseAuthenticatorData(rad.AuthData)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(ad.RelayingPartyIDHash, authData.RelayingPartyIDHash) {
		return nil, status.Error(codes.PermissionDenied, "Invalid CredentialID")
	}

	rawPeerPublic, err := sec.P256FromCose(ad.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return nil, err
	}

	peerPublic, err := sec.UnparsedPublicKey(elliptic.P256(), rawPeerPublic.Bytes())
	if err != nil {
		return nil, err
	}

	ok, err := verifySignature(rad.AuthData, rad.ClientData, rad.Signature, peerPublic)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, status.Error(codes.PermissionDenied, "Invalid Signature")
	}

	return &rpc.AuthorizationResult{Message: "Hello, vito.sartori!"}, nil
}

func verifySignature(authData, clientData, signature []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	hash := sha256.Sum256(clientData)
	message := append(authData, hash[:]...)
	digest := sha256.Sum256(message)
	valid := ecdsa.VerifyASN1(publicKey, digest[:], signature)
	return valid, nil
}
