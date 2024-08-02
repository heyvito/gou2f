package hid

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"github.com/heyvito/gou2f/cbor"
	"github.com/heyvito/gou2f/cose"
	"github.com/heyvito/gou2f/fido"
	"github.com/heyvito/gou2f/sec"
	"hash"
)

func (d *Device) Register(msg fido.MakeCredential) (*fido.RegisterAttestation, error) {
	res, err := d.sendCBOR(u2fRegister, msg)
	if err != nil {
		return nil, err
	}

	return fido.ParseRegisterAttestation(res)
}

func (d *Device) HashWithPinToken(fn func() hash.Hash, data []byte) ([]byte, error) {
	if d.pinToken == nil {
		return nil, fmt.Errorf("must call GetPin first")
	}
	digest := hmac.New(fn, d.pinToken.Key)
	digest.Write(data)
	return digest.Sum(nil), nil
}

func (d *Device) Assert(request fido.AssertionRequest) (*fido.AssertionResult, error) {
	res, err := d.sendCBOR(u2fAuthenticate, request)
	if err != nil {
		return nil, err
	}

	decoded, err := cbor.Unmarshal(res)
	if err != nil {
		return nil, err
	}
	ok, credID := cbor.MustBore[[]byte](decoded, "0->u:0x1->t:id")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}
	ok, credType := cbor.MustBore[string](decoded, "0->u:0x1->t:type")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}
	ok, authData := cbor.MustBore[[]byte](decoded, "0->u:0x2")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}
	ok, signature := cbor.MustBore[[]byte](decoded, "0->u:0x3")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}

	return &fido.AssertionResult{
		Credential: fido.PublicKeyCredentialDescriptor{
			Type: fido.PublicKeyCredentialType{
				Type: credType,
			},
			ID:         credID,
			Transports: nil,
		},
		AuthData:  authData,
		Signature: signature,
	}, nil
}

func (d *Device) GetVersion() (string, error) {
	res, err := d.sendAPDU(&APDURequest{
		Instruction: u2fVersion,
		ParameterA:  0,
		ParameterB:  0,
		Data:        nil,
	})
	if err != nil {
		return "", err
	}

	return string(res.Response), nil
}

func (d *Device) GetPin(userPin string) error {
	res, err := d.sendCBOR(ctapAuthenticatorClientPIN, fido.ClientPinGetKeyAgreement)
	if err != nil {
		return nil
	}
	decoded, err := cbor.Unmarshal(res)
	if err != nil {
		return err
	}
	ok, keyMap := cbor.MustBore[cbor.Map](decoded, "0->u:1")
	if !ok {
		return fmt.Errorf("invalid response from authenticator")
	}
	sharedKey := cose.NewKeyFromCBOR(keyMap)
	sharedSecret, err := sec.NewSharedSecret(sharedKey)
	if err != nil {
		return fmt.Errorf("failed initialising secret from shared key: %w", err)
	}
	d.sharedSecret = sharedSecret
	encodedPin, err := sharedSecret.EncryptPin(userPin)
	if err != nil {
		return fmt.Errorf("failed encrypting pin: %w", err)
	}

	getTokenData, err := fido.ClientPinGetToken(sharedSecret.PublicKey, encodedPin)
	if err != nil {
		return fmt.Errorf("failed fetching token data: %w", err)
	}

	res, err = d.sendCBOR(ctapAuthenticatorClientPIN, getTokenData)
	if err != nil {
		return err
	}

	token, err := extractTokenFromCBOR(res)
	if err != nil {
		return err
	}

	d.pinToken, err = d.sharedSecret.DecryptPinToken(token)

	return err
}

func (d *Device) GetCredentialManagementMetadata() (*fido.CredentialManagementResult, error) {
	if d.credMgmtIsPreview {
		return d.fidoPreviewGetMetadata()
	}

	return nil, fmt.Errorf("not implemented")
	//_, err := d.sendCBOR(ctapAuthenticatorCredentialManagement, fido.CredentialManagementRequest{
	//	SubCommand: ctapAuthenticatorCredMgmtGetCredsMetadata,
	//})
	//if err != nil {
	//	return nil, err
	//}
}

func (d *Device) GetInfo() (*fido.DeviceInfo, error) {
	data, err := d.sendCBOR(u2fGetInfo, nil)
	if err != nil {
		return nil, err
	}

	m, err := cbor.Unmarshal(data)

	dev := &fido.DeviceInfo{}

	dev.Versions = intoArray[string](cbor.MustBore[[]any](m, "0->u:0x1"))
	dev.Extensions = intoArray[string](cbor.MustBore[[]any](m, "0->u:0x2"))
	_, dev.AAGUID = cbor.MustBore[[]byte](m, "0->u:0x3")

	if ok, opts := cbor.MustBore[cbor.Map](m, "0->u:0x4"); ok {
		dev.Options = make(map[string]bool)
		for _, pair := range opts {
			dev.Options[pair.Key.(string)] = pair.Value.(bool)
		}
	}

	_, dev.MaxMessageSize = cbor.MustBore[uint16](m, "0->u:0x5")
	dev.PinUvAuthProtocols = intoArray[uint](cbor.MustBore[[]any](m, "0->u:0x6"))
	_, dev.CredentialCountInList = cbor.MustBore[uint](m, "0->u:0x7")
	_, dev.MaxCredentialIdLength = cbor.MustBore[uint8](m, "0->u:0x8")
	dev.Transports = intoArray[string](cbor.MustBore[[]any](m, "0->u:0x9"))

	if ok, rawAlgs := cbor.MustBore[[]any](m, "0->u:0xA"); ok {
		algs := intoArray[cbor.Map](true, rawAlgs)
		dev.Algorithms = make([]fido.PublicKeyCredentialType, len(algs))
		for i, v := range algs {
			dev.Algorithms[i].Type, _ = cbor.MapGetKey[string](v, "type")
			dev.Algorithms[i].Alg, _ = cbor.MapGetKey[int](v, "alg")
		}
	}

	_, dev.MinPINLength = cbor.MustBore[uint](m, "0->u:0xD")
	_, dev.FirmwareVersion = cbor.MustBore[uint32](m, "0->u:0xE")

	return dev, nil
}

func (d *Device) fidoPreviewGetMetadata() (*fido.CredentialManagementResult, error) {
	pinAuth, err := d.HashWithPinToken(sha256.New, []byte{0x01})
	if err != nil {
		return nil, err
	}
	res, err := d.sendCBOR(ctapAuthenticatorCredentialManagementPreview, &fido.CredentialManagementPreviewRequest{
		SubCommand:  0x01,
		PinProtocol: 0x01,
		PinAuth:     pinAuth[:16],
	})

	if err != nil {
		return nil, err
	}

	return fido.DecodeCredentialManagementResult(res)
}

func (d *Device) EnumerateRPs() ([]fido.EnumeratedRelayingParty, error) {
	if d.credMgmtIsPreview {
		return d.fidoPreviewEnumerateRPs()
	}

	return nil, fmt.Errorf("not implemented")
}

func (d *Device) fidoPreviewEnumerateRPs() ([]fido.EnumeratedRelayingParty, error) {
	pinAuth, err := d.HashWithPinToken(sha256.New, []byte{0x02})
	if err != nil {
		return nil, err
	}
	res, err := d.sendCBOR(ctapAuthenticatorCredentialManagementPreview, &fido.CredentialManagementPreviewRequest{
		SubCommand:  0x02,
		PinProtocol: 0x01,
		PinAuth:     pinAuth[:16],
	})
	if err != nil {
		return nil, err
	}

	r, err := fido.DecodeCredentialManagementResult(res)
	if err != nil {
		return nil, err
	}

	if r.TotalRPs == 0 {
		return nil, nil
	}

	enumeratedRPs := make([]fido.EnumeratedRelayingParty, 0, r.TotalRPs)
	enumeratedRPs = append(enumeratedRPs, fido.EnumeratedRelayingParty{
		RelayingParty: *r.RP,
		RPIDHash:      r.RPIDHash,
	})

	for range r.TotalRPs - 1 {
		res, err := d.sendCBOR(ctapAuthenticatorCredentialManagementPreview, &fido.CredentialManagementPreviewRequest{
			SubCommand:  0x03,
			PinProtocol: 0x01,
			PinAuth:     pinAuth[:16],
		})
		if err != nil {
			return nil, err
		}

		r, err := fido.DecodeCredentialManagementResult(res)
		if err != nil {
			return nil, err
		}

		enumeratedRPs = append(enumeratedRPs, fido.EnumeratedRelayingParty{
			RelayingParty: *r.RP,
			RPIDHash:      r.RPIDHash,
		})
	}

	return enumeratedRPs, nil
}

func (d *Device) EnumerateRelayingPartyCredentials(relayingPartyHash []byte) ([]fido.EnumeratedCredential, error) {
	if d.credMgmtIsPreview {
		return d.fidoPreviewEnumerateCreds(relayingPartyHash)
	}

	return nil, fmt.Errorf("not implemented")
}

func (d *Device) fidoPreviewEnumerateCreds(relayingPartyHash []byte) ([]fido.EnumeratedCredential, error) {
	subCmdParams := &fido.CredentialManagementPreviewRequestParams{RPIDHash: relayingPartyHash}
	data, err := cbor.Marshal(subCmdParams)
	if err != nil {
		return nil, err
	}

	pinAuth, err := d.HashWithPinToken(sha256.New, append([]byte{0x04}, data...))
	if err != nil {
		return nil, err
	}
	res, err := d.sendCBOR(ctapAuthenticatorCredentialManagementPreview, &fido.CredentialManagementPreviewRequest{
		SubCommand:       0x04,
		PinProtocol:      0x01,
		SubCommandParams: subCmdParams,
		PinAuth:          pinAuth[:16],
	})
	if err != nil {
		return nil, err
	}

	r, err := fido.DecodeCredentialManagementResult(res)
	if err != nil {
		return nil, err
	}

	if r.TotalCredentials == 0 {
		return nil, nil
	}

	creds := make([]fido.EnumeratedCredential, 0, r.TotalCredentials)
	creds = append(creds, fido.EnumeratedCredential{
		User:                       r.User,
		CredentialID:               r.CredentialID,
		CredentialProtectionPolicy: r.CredProtect,
	})

	for range r.TotalCredentials - 1 {
		res, err := d.sendCBOR(ctapAuthenticatorCredentialManagementPreview, &fido.CredentialManagementPreviewRequest{
			SubCommand: 0x05,
		})
		if err != nil {
			return nil, err
		}

		r, err := fido.DecodeCredentialManagementResult(res)
		if err != nil {
			return nil, err
		}
		creds = append(creds, fido.EnumeratedCredential{
			User:                       r.User,
			CredentialID:               r.CredentialID,
			CredentialProtectionPolicy: r.CredProtect,
		})
	}

	return creds, nil
}

func (d *Device) DeleteCredential(id *fido.FlatPublicKeyCredentialDescriptor) error {
	if d.credMgmtIsPreview {
		return d.fidoPreviewDeleteCredential(id)
	}

	return fmt.Errorf("not implemented")
}

func (d *Device) fidoPreviewDeleteCredential(id *fido.FlatPublicKeyCredentialDescriptor) error {
	subCmdParams := &fido.CredentialManagementPreviewRequestParams{CredentialID: id}
	data, err := cbor.Marshal(subCmdParams)
	if err != nil {
		return err
	}

	pinAuth, err := d.HashWithPinToken(sha256.New, append([]byte{0x06}, data...))
	if err != nil {
		return err
	}

	_, err = d.sendCBOR(ctapAuthenticatorCredentialManagementPreview, &fido.CredentialManagementPreviewRequest{
		SubCommand:       0x06,
		PinProtocol:      0x01,
		SubCommandParams: subCmdParams,
		PinAuth:          pinAuth[:16],
	})

	return err
}
