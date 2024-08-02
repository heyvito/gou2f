package fido

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/heyvito/gou2f/cbor"
	"github.com/heyvito/gou2f/cose"
	"strings"
)

type Capabilities byte

const (
	WinkCapability Capabilities = 0x01
	CBORCapability Capabilities = 0x04
	NMSGCapability Capabilities = 0x08
)

func (c Capabilities) Includes(o Capabilities) bool {
	return c&o == o
}

func (c Capabilities) String() string {
	var caps []string
	if c&WinkCapability == WinkCapability {
		caps = append(caps, "WINK")
	}
	if c&CBORCapability == CBORCapability {
		caps = append(caps, "CBOR")
	}
	if c&NMSGCapability == NMSGCapability {
		caps = append(caps, "NMSG")
	}
	return strings.Join(caps, ", ")
}

type InitResponse struct {
	Nonce          []byte
	ChannelID      uint32
	CTAPHIDVersion byte
	VersionMajor   byte
	VersionMinor   byte
	VersionBuild   byte
	Capabilities   Capabilities
}

func (i *InitResponse) String() string {
	value := []string{
		fmt.Sprintf("Nonce: %s", hex.EncodeToString(i.Nonce)),
		fmt.Sprintf("ChannelID: %d", i.ChannelID),
		fmt.Sprintf("CTAPHIDVersion: %d", i.CTAPHIDVersion),
		fmt.Sprintf("VersionMajor: %d", i.VersionMajor),
		fmt.Sprintf("VersionMinor: %d", i.VersionMinor),
		fmt.Sprintf("VersionBuild: %d", i.VersionBuild),
		fmt.Sprintf("Capabilities: %s", i.Capabilities),
	}

	return fmt.Sprintf("{InitResponse %s}", strings.Join(value, ", "))

}

type MakeCredential struct {
	ClientDataHash   []byte                          `cbor:"u8:0x1,omitempty"`
	RelayingParty    *RelayingParty                  `cbor:"u8:0x2,omitempty"`
	User             *UserEntity                     `cbor:"u8:0x3,omitempty"`
	PubKeyCredParams []PublicKeyCredentialType       `cbor:"u8:0x4,omitempty"`
	ExcludeList      []PublicKeyCredentialDescriptor `cbor:"u8:0x5,omitempty"`
	Extensions       map[string]any                  `cbor:"u8:0x6,omitempty"`
	Options          *AuthOpts                       `cbor:"u8:0x7,omitempty"`
	PinAuth          []byte                          `cbor:"u8:0x8,omitempty"`
	PinProtocol      *int                            `cbor:"u8:0x9,omitempty"`
}

type RelayingParty struct {
	Name string `cbor:"name"`
	ID   string `cbor:"id"`
}

type UserEntity struct {
	ID          []byte `cbor:"id"`
	DisplayName string `cbor:"displayName"`
	Name        string `cbor:"name"`
}

type PublicKeyCredentialType struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}

type PublicKeyCredentialDescriptor struct {
	Type       PublicKeyCredentialType `cbor:"type"`
	ID         []byte                  `cbor:"id"`
	Transports []string                `cbor:"transports"`
}

type FlatPublicKeyCredentialDescriptor struct {
	Type string `cbor:"type"`
	ID   []byte `cbor:"id"`
}

type AuthOpts struct {
	ResidentKey      *bool `cbor:"rk,omitempty"`
	UserVerification *bool `cbor:"uv,omitempty"`
}

var ClientPinGetKeyAgreement = map[uint8]any{
	0x01: 0x01, // Pin Protocol (Static)
	0x02: 0x02, // Get Key Agreement
}

func ClientPinGetToken(key *cose.Key, pinHash []byte) (any, error) {
	ok, keyCurve := cose.KeyParamAs[uint](key, -1)
	if !ok {
		return nil, fmt.Errorf("invalid key parameter")
	}
	ok, keyX := cose.KeyParamAs[[]byte](key, -2)
	if !ok {
		return nil, fmt.Errorf("invalid key parameter")
	}
	ok, keyY := cose.KeyParamAs[[]byte](key, -3)
	if !ok {
		return nil, fmt.Errorf("invalid key parameter")
	}
	return map[uint8]any{
		0x01: 0x01, // Pin Protocol (Static)
		0x02: 0x05, // Get Pin Token
		0x03: map[int]any{
			-1: keyCurve,
			-2: keyX,
			-3: keyY,
		},
		0x06: pinHash,
	}, nil
}

type AttestationStatement struct {
	Algorithm int32
	Signature []byte
	X5C       []byte
}

func ParseRegisterAttestation(data []byte) (*RegisterAttestation, error) {
	decoded, err := cbor.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal registration response: %w", err)
	}

	ok, format := cbor.MustBore[string](decoded, "0->u:0x1")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}

	ok, authData := cbor.MustBore[[]byte](decoded, "0->u:0x2")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}

	ok, alg := cbor.MustBore[int](decoded, "0->u:0x3->t:alg")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}

	ok, sig := cbor.MustBore[[]byte](decoded, "0->u:0x3->t:sig")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}

	ok, x5c := cbor.MustBore[[]byte](decoded, "0->u:0x3->t:x5c->0")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}

	return &RegisterAttestation{
		Format:   format,
		AuthData: authData,
		AttestationStatement: AttestationStatement{
			Algorithm: int32(alg),
			Signature: sig,
			X5C:       x5c,
		},
	}, nil
}

type RegisterAttestation struct {
	Format               string
	AuthData             []byte
	AttestationStatement AttestationStatement
}

func (r *RegisterAttestation) AuthenticatorData() (*AuthenticatorData, error) {
	return ParseAuthenticatorData(r.AuthData)
}

func ParseAuthenticatorData(data []byte) (*AuthenticatorData, error) {
	a := &AuthenticatorData{}
	reader := bufio.NewReader(bytes.NewReader(data))
	var err error
	a.RelayingPartyIDHash = make([]byte, 32)
	if _, err = reader.Read(a.RelayingPartyIDHash); err != nil {
		return nil, err
	}
	if a.Flags, err = reader.ReadByte(); err != nil {
		return nil, err
	}
	if err = binary.Read(reader, binary.BigEndian, &a.SignCount); err != nil {
		return nil, err
	}

	if a.HasAttestedCredentialData() {
		ac := AttestedCredentialData{}
		ac.AAGUID = make([]byte, 16)
		if _, err = reader.Read(ac.AAGUID); err != nil {
			return nil, err
		}
		if err = binary.Read(reader, binary.BigEndian, &ac.CredentialLength); err != nil {
			return nil, err
		}
		ac.CredentialID = make([]byte, ac.CredentialLength)
		if _, err = reader.Read(ac.CredentialID); err != nil {
			return nil, err
		}
		var cborData []any
		if cborData, err = cbor.UnmarshalOne(reader); err != nil {
			return nil, err
		}
		ok, coseMap := cbor.MustBore[cbor.Map](cborData, "0")
		if !ok {
			return nil, fmt.Errorf("invalid authentication data")
		}
		ac.CredentialPublicKey = cose.NewKeyFromCBOR(coseMap)
		a.AttestedCredentialData = &ac
	}

	if a.HasExtensions() {
		dec, err := cbor.UnmarshalReader(reader)
		if err != nil {
			return nil, err
		}
		a.Extensions = make(map[string]any)
		ok, cMap := cbor.MustBore[cbor.Map](dec, "0")
		if ok {
			for _, v := range cMap {
				if k, ok := v.Key.(string); ok {
					a.Extensions[k] = v.Value
				}
			}
		}
	}
	return a, nil
}

type AuthenticatorData struct {
	RelayingPartyIDHash    []byte
	Flags                  byte
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             map[string]any
}

func (a AuthenticatorData) UserPresent() bool  { return a.Flags&0x1 == 0x1 }
func (a AuthenticatorData) UserVerified() bool { return a.Flags&0x4 == 0x4 }
func (a AuthenticatorData) HasAttestedCredentialData() bool {
	return a.Flags&0x40 == 0x40
}
func (a AuthenticatorData) HasExtensions() bool { return a.Flags&0x80 == 0x80 }

type AttestedCredentialData struct {
	AAGUID              []byte
	CredentialLength    uint16
	CredentialID        []byte
	CredentialPublicKey *cose.Key
}

type AssertionRequest struct {
	RelayingPartyID string `cbor:"u8:0x1"`
	ClientDataHash  []byte `cbor:"u8:0x2"`
}

type AssertionResult struct {
	Credential PublicKeyCredentialDescriptor
	AuthData   []byte
	Signature  []byte
}

func (a AssertionResult) ParseAuthData() (*AuthenticatorData, error) {
	return ParseAuthenticatorData(a.AuthData)
}

type CredentialManagementRequest struct {
	SubCommand        byte                              `cbor:"u8:0x1"`
	SubCommandParams  CredentialManagementRequestParams `cbor:"u8:0x2"`
	PinUvAuthProtocol uint8                             `cbor:"u8:0x3"`
	PinUvAuthParam    []byte                            `cbor:"u8:0x4"`
}

type CredentialManagementRequestParams struct {
	RPIDHash     []byte                         `cbor:"u8:0x1,omitempty"`
	CredentialID *PublicKeyCredentialDescriptor `cbor:"u8:0x2,omitempty"`
	User         *UserEntity                    `cbor:"u8:0x3,omitempty"`
}

type CredentialManagementResult struct {
	ExistingResidentCredentialsCount             uint                               `cbor:"u8:0x1"`
	MaxPossibleRemainingResidentCredentialsCount uint                               `cbor:"u8:0x2"`
	RP                                           *RelayingParty                     `cbor:"u8:0x3"`
	RPIDHash                                     []byte                             `cbor:"u8:0x4"`
	TotalRPs                                     uint                               `cbor:"u8:0x5"`
	User                                         *UserEntity                        `cbor:"u8:0x6"`
	CredentialID                                 *FlatPublicKeyCredentialDescriptor `cbor:"u8:0x7"`
	PublicKey                                    *cose.Key                          `cbor:"u8:0x8"`
	TotalCredentials                             uint                               `cbor:"u8:0x9"`
	CredProtect                                  uint                               `cbor:"u8:0xA"`
	LargeBlobKey                                 []byte                             `cbor:"u8:0xB"`
	ThirdPartyPayment                            bool                               `cbor:"u8:0xC"`
}

func DecodeCredentialManagementResult(data []byte) (*CredentialManagementResult, error) {
	decoded, err := cbor.Unmarshal(data)
	if err != nil {
		return nil, err
	}
	r := &CredentialManagementResult{}
	_, r.ExistingResidentCredentialsCount = cbor.MustBore[uint](decoded, "0->u:0x1")
	_, r.MaxPossibleRemainingResidentCredentialsCount = cbor.MustBore[uint](decoded, "0->u:0x2")
	if ok, v := cbor.MustBore[cbor.Map](decoded, "0->u:0x3"); ok {
		r.RP = &RelayingParty{}
		r.RP.ID, _ = cbor.MapGetKey[string](v, "id")
	}
	_, r.RPIDHash = cbor.MustBore[[]byte](decoded, "0->u:0x4")
	_, r.TotalRPs = cbor.MustBore[uint](decoded, "0->u:0x5")
	if ok, v := cbor.MustBore[cbor.Map](decoded, "0->u:0x6"); ok {
		r.User = &UserEntity{}
		r.User.ID, _ = cbor.MapGetKey[[]byte](v, "id")
		r.User.Name, _ = cbor.MapGetKey[string](v, "name")
		r.User.DisplayName, _ = cbor.MapGetKey[string](v, "displayName")
	}
	if ok, v := cbor.MustBore[cbor.Map](decoded, "0->u:0x7"); ok {
		r.CredentialID = &FlatPublicKeyCredentialDescriptor{}
		r.CredentialID.ID, _ = cbor.MapGetKey[[]byte](v, "id")
		r.CredentialID.Type, _ = cbor.MapGetKey[string](v, "type")
	}
	if ok, v := cbor.MustBore[cbor.Map](decoded, "0->u:0x8"); ok {
		r.PublicKey = cose.NewKeyFromCBOR(v)
	}
	_, r.TotalCredentials = cbor.MustBore[uint](decoded, "0->u:0x9")
	_, r.CredProtect = cbor.MustBore[uint](decoded, "0->u:0xA")
	return r, nil
}

type DeviceInfo struct {
	Versions                         []string                  `cbor:"u8:0x1"`
	Extensions                       []string                  `cbor:"u8:0x2"`
	AAGUID                           []byte                    `cbor:"u8:0x3"`
	Options                          map[string]bool           `cbor:"u8:0x4"`
	MaxMessageSize                   uint16                    `cbor:"u8:0x5"`
	PinUvAuthProtocols               []uint                    `cbor:"u8:0x6"`
	CredentialCountInList            uint                      `cbor:"u8:0x7"`
	MaxCredentialIdLength            uint8                     `cbor:"u8:0x8"`
	Transports                       []string                  `cbor:"u8:0x9"`
	Algorithms                       []PublicKeyCredentialType `cbor:"u8:0xA"`
	MaxSerializedLargeBlobArray      uint32                    `cbor:"u8:0xB"`
	ForcePINChange                   bool                      `cbor:"u8:0xC"`
	MinPINLength                     uint                      `cbor:"u8:0xD"`
	FirmwareVersion                  uint32                    `cbor:"u8:0xE"`
	MaxCredBlobLength                uint32                    `cbor:"u8:0xF"`
	MaxRPIDsForSetMinPinLength       uint32                    `cbor:"u8:0x10"`
	PreferredPlatformUVAttempts      uint32                    `cbor:"u8:0x11"`
	UVModality                       uint32                    `cbor:"u8:0x12"`
	Certifications                   map[any]any               `cbor:"u8:0x13"`
	RemainingDiscoverableCredentials uint32                    `cbor:"u8:0x14"`
	VendorPrototypeConfigCommands    []uint32                  `cbor:"u8:0x15"`
	AttestationFormats               []string                  `cbor:"u8:0x16"`
	UVCountSinceLastPinEntry         uint32                    `cbor:"u8:0x17"`
	LongTouchForReset                bool                      `cbor:"u8:0x18"`
}

func (d *DeviceInfo) IncludesVersion(v string) bool {
	for _, ver := range d.Versions {
		if ver == v {
			return true
		}
	}
	return false
}

type CredentialManagementPreviewRequest struct {
	SubCommand       byte                                      `cbor:"u8:0x1"`
	SubCommandParams *CredentialManagementPreviewRequestParams `cbor:"u8:0x2,omitempty"`
	PinProtocol      uint8                                     `cbor:"u8:0x3"`
	PinAuth          []byte                                    `cbor:"u8:0x4"`
}

type CredentialManagementPreviewRequestParams struct {
	RPIDHash     []byte                             `cbor:"u8:0x1,omitempty"`
	CredentialID *FlatPublicKeyCredentialDescriptor `cbor:"u8:0x2,omitempty"`
}

type EnumeratedRelayingParty struct {
	RelayingParty RelayingParty
	RPIDHash      []byte
}

type EnumeratedCredential struct {
	User                       *UserEntity
	CredentialID               *FlatPublicKeyCredentialDescriptor
	CredentialProtectionPolicy any
}
