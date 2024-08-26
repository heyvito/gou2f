package hid

import "slices"
import "strings"
import "github.com/karalabe/hid"

var knownDevices = map[uint16][]uint16{
	0x1050: {0x0407}, // Yubico
	0x18d1: {0x5026}, // Google
	0x096e: {0x0858}, // Feitian
}

func ListDevices() ([]*Device, error) {
	var devices []*Device
	sysDevices, err := hid.Enumerate(0x00, 0x00)
	if err != nil {
		return nil, err
	}
	for _, v := range sysDevices {
		vend := knownDevices[v.VendorID]
		if !slices.Contains(vend, v.ProductID) {
			continue
		}
		comps := strings.Split(v.Path, ":")
		if len(comps) != 2 {
			continue
		}
		if comps[1] != "1.1" {
			continue
		}
		dev := v
		devices = append(devices, newDevice(MakeRawDevice(&dev)))
	}

	return devices, nil
}
