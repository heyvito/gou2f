package hid

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/heyvito/gou2f/cbor"
	"github.com/heyvito/gou2f/fido"
	"github.com/heyvito/gou2f/sec"
	"github.com/karalabe/hid"
	"io"
)

// The HID message structure is defined at the following url.
// https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-hid-protocol-v1.1-id-20160915.html

var enc = binary.BigEndian

const u2fDebug = false

type APDURequest struct {
	Instruction uint8
	ParameterA  uint8
	ParameterB  uint8
	Data        []byte
}

func (a *APDURequest) Encode() []byte {
	buffer := NewBuffer(8 + len(a.Data))
	buffer.
		Bytes(0, a.Instruction, a.ParameterA, a.ParameterB).
		Int24(uint32(len(a.Data))).
		Data(a.Data).
		Bytes(0x04, 0x00)
	return buffer.data
}

type APDUResponse struct {
	Status   uint16
	Response []byte
}

func (a *APDUResponse) Error() error {
	if a.Status == uint16(errNone) || a.Status == u2fSwNoError {
		return nil
	}
	return fmt.Errorf("HID error 0x0%2x", a.Status)
}

type baseDevice interface {
	Open() error
	Close() error
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}

func ListDevices() ([]*Device, error) {
	var devices []*Device
	sysDevices, err := hid.Enumerate(0x00, 0x00)
	if err != nil {
		return nil, err
	}
	for _, v := range sysDevices {
		if v.UsagePage == fidoUsagePage && v.Usage == uint16(fidoUsageU2FHID) {
			dev := v
			devices = append(devices, newDevice(MakeRawDevice(&dev)))
		}
	}

	return devices, nil
}

func newDevice(dev baseDevice) *Device {
	return &Device{
		device:       dev,
		channelID:    cidBroadcast,
		randomReader: rand.Reader,
		deviceInfo:   nil,
	}
}

type Device struct {
	device            baseDevice
	channelID         uint32
	randomReader      io.Reader
	sharedSecret      *sec.SharedSecret
	pinToken          *sec.PinToken
	deviceInfo        *fido.DeviceInfo
	credMgmtIsPreview bool
}

func (d *Device) Open() (*fido.InitResponse, error) {
	err := d.device.Open()
	if err != nil {
		return nil, err
	}

	return d.tryInitDevice()
}

func (d *Device) tryInitDevice() (*fido.InitResponse, error) {
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(d.randomReader, nonce); err != nil {
		return nil, err
	}

	if err := d.request(u2fHIDInit, nonce); err != nil {
		return nil, err
	}

	resp, err := d.response(u2fHIDInit)
	if err != nil {
		return nil, err
	}

	for !bytes.Equal(resp[:8], nonce) {
		if resp, err = d.response(u2fHIDInit); err != nil {
			return nil, err
		}
	}

	init := &fido.InitResponse{
		Nonce:          resp[:8],
		ChannelID:      enc.Uint32(resp[8:12]),
		CTAPHIDVersion: resp[12],
		VersionMajor:   resp[13],
		VersionMinor:   resp[14],
		VersionBuild:   resp[15],
		Capabilities:   fido.Capabilities(resp[16]),
	}

	d.channelID = init.ChannelID
	d.deviceInfo, err = d.GetInfo()
	if err != nil {
		return nil, err
	}

	d.credMgmtIsPreview = d.deviceInfo.IncludesVersion("FIDO_2_1_PRE") && d.deviceInfo.Options["credentialMgmtPreview"]

	return init, nil
}

func (d *Device) request(command byte, data []byte) error {
	maxData := min(uint16(len(data)), hidReportSize-7)
	offset := maxData
	sequence := uint8(0)

	buffer := make([]byte, hidReportSize+1)
	enc.PutUint32(buffer[1:], d.channelID)
	buffer[5] = typeInit | command
	enc.PutUint16(buffer[6:], uint16(len(data)))
	copy(buffer[8:], data[:maxData])

	if _, err := d.device.Write(buffer); err != nil {
		return err
	}

	for offset < uint16(len(data)) {
		for i := range buffer {
			buffer[i] = 0
		}
		toCopy := min(uint16(len(data)-int(offset)), hidReportSize-5)
		enc.PutUint32(buffer[1:], d.channelID)
		buffer[5] = 0x7f & sequence
		copy(buffer[6:], data[offset:offset+toCopy])

		if _, err := d.device.Write(buffer); err != nil {
			return err
		}
		sequence++
		offset += toCopy
	}

	return nil
}

func (d *Device) response(command byte) ([]byte, error) {
	header := make([]byte, 5)
	enc.PutUint32(header, d.channelID)
	header[4] = typeInit | command
	response := make([]byte, hidReportSize)
	for !bytes.Equal(header, response[:5]) {
		if _, err := d.device.Read(response); err != nil {
			return nil, err
		}
		if bytes.Equal(response[:4], header[:4]) && response[4] == u2fHIDError {
			return nil, fmt.Errorf("HIDError: 0x%02x", response[6])
		}
	}

	dataLen := enc.Uint16(response[5:7])
	data := make([]byte, dataLen)
	totalRead := min(dataLen, hidReportSize-7)
	copy(data, response[7:7+totalRead])
	var seq uint8 = 0
	response = make([]byte, hidReportSize)
	for totalRead < dataLen {
		if _, err := d.device.Read(response); err != nil {
			return nil, err
		}
		if !bytes.Equal(response[:4], header[:4]) {
			return nil, fmt.Errorf("received incorrect channel ID from device")
		}

		if response[4] != seq&0x7f {
			return nil, fmt.Errorf("received incorrect sequence number from device")
		}

		seq++
		partLen := min(hidReportSize-5, dataLen-totalRead)
		copy(data[totalRead:totalRead+partLen], response[5:5+partLen])
		totalRead += partLen
	}

	return data, nil
}

func (d *Device) sendAPDU(req *APDURequest) (*APDUResponse, error) {
	if err := d.request(u2fHIDMessage, req.Encode()); err != nil {
		return nil, err
	}

	resp, err := d.response(u2fHIDMessage)
	if err != nil {
		return nil, err
	}

	result := &APDUResponse{
		Status:   enc.Uint16(resp[len(resp)-2:]),
		Response: resp[:len(resp)-2],
	}

	if err = result.Error(); err != nil {
		return nil, err
	}

	return result, nil
}

func (d *Device) sendCBOR(command byte, object any) ([]byte, error) {
	data, err := cbor.Marshal(object)
	if err != nil {
		return nil, err
	}

	if u2fDebug {
		fmt.Printf("Outbound CBOR message: (0x%02x) %s\n", command, hex.EncodeToString(data))
	}
	data = append([]byte{command}, data...)

	if err = d.request(u2fHIDCTAPCBOR, data); err != nil {
		return nil, err
	}

	res, err := d.response(u2fHIDCTAPCBOR)
	if err != nil {
		return nil, err
	}
	if res[0] != 0x00 {
		return nil, CTAPError(res[0])
	}
	if u2fDebug {
		fmt.Printf("Inbound CBOR message: %s\n", hex.EncodeToString(res[1:]))
	}
	return res[1:], nil
}

func extractTokenFromCBOR(res []byte) ([]byte, error) {
	dec, err := cbor.Unmarshal(res)
	if err != nil {
		return nil, err
	}
	ok, data := cbor.MustBore[[]byte](dec, "0->u:0x02")
	if !ok {
		return nil, fmt.Errorf("invalid response from authenticator")
	}
	return data, nil
}

func intoArray[T any](_ bool, v []interface{}) []T {
	arr := make([]T, len(v))
	for i, v := range v {
		arr[i] = v.(T)
	}
	return arr
}
