package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/heyvito/gou2f/example/rpc"
	"github.com/heyvito/gou2f/fido"
	"github.com/heyvito/gou2f/hid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	devices, err := hid.ListDevices()
	if err != nil {
		panic(err)
	}
	var dev *hid.Device
	for _, v := range devices {
		init, err := v.Open()
		if err != nil {
			continue
		}
		fmt.Printf("%s\n", init)
		dev = v
		break
	}

	if dev == nil {
		panic("no devices!")
	}

	panic("Insert your pin below")
	err = dev.GetPin("")
	if err != nil {
		panic(err)
	}

	dataHash := make([]byte, 32)
	_, err = rand.Read(dataHash)
	if err != nil {
		panic(err)
	}

	userID := make([]byte, 32)
	_, err = rand.Read(userID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("DataHash: %s\n", hex.EncodeToString(dataHash))
	pinAuthData, err := dev.HashWithPinToken(sha256.New, dataHash)
	if err != nil {
		panic(err)
	}
	fmt.Printf("pinAuthData: %s\n", hex.EncodeToString(pinAuthData[:16]))

	//res, err := dev.Register(fido.MakeCredential{
	//	ClientDataHash: dataHash,
	//	RelayingParty: &fido.RelayingParty{
	//		Name: "microca.test",
	//		ID:   "microca.test",
	//	},
	//	User: &fido.UserEntity{
	//		ID:          userID,
	//		Name:        "Vito Sartori",
	//		DisplayName: "vito.sartori",
	//	},
	//	PubKeyCredParams: []fido.PublicKeyCredentialType{
	//		{Type: "public-key", Alg: -7},
	//		{Type: "public-key", Alg: -257},
	//	},
	//	PinAuth:     pinAuthData,
	//	PinProtocol: fido.Int(1),
	//	Options: &fido.AuthOpts{
	//		ResidentKey: fido.Bool(true),
	//	},
	//})
	//
	//if err != nil {
	//	panic(err)
	//}
	//
	//fmt.Println(res)

	clientData := make([]byte, 64)
	_, err = rand.Read(clientData)
	if err != nil {
		panic(err)
	}

	digest := sha256.Sum256(clientData)
	assertResult, err := dev.Assert(fido.AssertionRequest{
		RelayingPartyID: "microca.test",
		ClientDataHash:  digest[:],
	})
	if err != nil {
		panic(err)
	}
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient("localhost:9090", opts...)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	cli := rpc.NewExampleClient(conn)
	msg, err := cli.Authenticate(context.TODO(), &rpc.AuthorizationData{
		ClientData:   clientData,
		CredentialID: assertResult.Credential.ID,
		AuthData:     assertResult.AuthData,
		Signature:    assertResult.Signature,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(msg.Message)
}
