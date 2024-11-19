// Package banner provides simple banner grab and matching implementation of the zgrab2.Module.
// It sends a customizble probe (default to "\n") and filters the results based on custom regexp (--pattern)

package mc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	Probe1 string `long:"probe1" default:"\\n" description:"Probe to send to the server. Use triple slashes to escape, for example \\\\\\n is literal \\n. Mutually exclusive with --probe-file."`
	Probe2 string `long:"probe2" default:"\\n" description:"Second probe to send to the server. Use triple slashes to escape, for example \\\\\\n is literal \\n. Mutually exclusive with --probe-file."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	probe1 []byte
	probe2 []byte
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Banner1 string `json:"banner1,omitempty"`
	Banner2 string `json:"banner2,omitempty"`
}

// RegisterModule is called by modules/mc.go to register the scanner.
func RegisterModule() {
	var m Module
	_, err := zgrab2.AddCommand("mc", "MC", m.Description(), 80, &m)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// GetName returns the Scanner name defined in the Flags.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (s *Scanner) Protocol() string {
	return "mc"
}

// InitPerSender initializes the scanner for a given sender.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Fetch a raw banner by sending a static probe and checking the result against a regular expression"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	{
		strProbe, err := strconv.Unquote(fmt.Sprintf(`"%s"`, s.config.Probe1))
		if err != nil {
			panic("Probe error")
		}
		s.probe1 = []byte(strProbe)
	}
	{
		strProbe2, err := strconv.Unquote(fmt.Sprintf(`"%s"`, s.config.Probe2))
		if err != nil {
			panic("Probe error")
		}
		s.probe2 = []byte(strProbe2)
	}
	return nil
}

func readVarInt(conn net.Conn) (int, error) {
	var result int
	var shift uint
	const maxBytes = 5
	for i := 0; i < maxBytes; i++ {
		var b [1]byte
		_, err := conn.Read(b[:])
		if err != nil {
			return 0, err
		}
		result |= int(b[0]&0x7F) << shift
		if b[0]&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("varint too long")
}

func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var (
		conn    net.Conn
		err     error
		readErr error
	)

	conn, err = target.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	_, err = conn.Write(s.probe1)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	var length int
	length, readErr = readVarInt(conn)
	if readErr != nil {
		return zgrab2.TryGetScanStatus(readErr), nil, readErr
	}

	if length > 32800 {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("banner too long")
	}
	if length < 1 {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("zero/negative banner length")
	}

	data := make([]byte, length)
	totalRead := 0
	timeout := time.After(5 * time.Second)

readLoop:
	for totalRead < length {
		select {
		case <-timeout:
			return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("read timeout")
		default:
			n, err := conn.Read(data[totalRead:])
			if err != nil && err != io.EOF {
				return zgrab2.TryGetScanStatus(err), nil, err
			}
			totalRead += n
			if err == io.EOF {
				break readLoop
			}
		}
	}

	_, err = conn.Write(s.probe2)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	length, readErr = readVarInt(conn)
	if readErr != nil {
		return zgrab2.TryGetScanStatus(readErr), nil, readErr
	}

	if length != 9 {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("banner length mismatch")
	}

	data2 := make([]byte, length)
	totalRead = 0
	timeout = time.After(5 * time.Second)

readLoop2:
	for totalRead < length {
		select {
		case <-timeout:
			return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("read timeout")
		default:
			n, err := conn.Read(data2[totalRead:])
			if err != nil && err != io.EOF {
				return zgrab2.TryGetScanStatus(err), nil, err
			}
			totalRead += n
			if err == io.EOF {
				break readLoop2
			}
		}
	}

	var results Results

	results.Banner1 = hex.EncodeToString(data)
	results.Banner2 = hex.EncodeToString(data2)

	return zgrab2.SCAN_SUCCESS, &results, nil
}
