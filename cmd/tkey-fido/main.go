// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/pflag"
	"github.com/tillitis/tillitis-key1-apps/internal/util"
	"github.com/tillitis/tillitis-key1-apps/tk1"
)

// Use when printing err/diag msgs
var le = log.New(os.Stderr, "", 0)

const progname = "tkey-fido"

var version string

func main() {
	exit := func(code int) {
		os.Exit(code)
	}

	if version == "" {
		version = readBuildInfo()
	}

	var devPath, fileUSS, pinentry string
	var speed int
	var enterUSS, listPortsOnly, testOnly, versionOnly, helpOnly bool
	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.BoolVarP(&listPortsOnly, "list-ports", "L", false,
		"List possible serial ports to use with --port.")
	pflag.StringVar(&devPath, "port", "",
		"Set serial port device `PATH`. If this is not passed, auto-detection will be attempted.")
	pflag.IntVar(&speed, "speed", tk1.SerialSpeed,
		"Set serial port speed in `BPS` (bits per second).")
	pflag.BoolVar(&enterUSS, "uss", false,
		// TODO revise, and should we use USS?
		"Enable typing of a phrase to be hashed as the User Supplied Secret. The USS is loaded onto the TKey along with the app itself. A different USS results in different SSH public/private keys, meaning a different identity.")
	pflag.StringVar(&fileUSS, "uss-file", "",
		"Read `FILE` and hash its contents as the USS. Use '-' (dash) to read from stdin. The full contents are hashed unmodified (e.g. newlines are not stripped).")
	pflag.StringVar(&pinentry, "pinentry", "",
		"Pinentry `PROGRAM` for use by --uss. The default is found by looking in your gpg-agent.conf for pinentry-program, or 'pinentry' if not found there.")
	pflag.BoolVar(&testOnly, "test", false, "Run a simple U2F register/authenticate test towards the app on the TKey, then exit.")
	pflag.BoolVar(&versionOnly, "version", false, "Output version information.")
	pflag.BoolVar(&helpOnly, "help", false, "Output this help.")
	pflag.Usage = func() {
		desc := fmt.Sprintf(`Usage: %[1]s -L [flags...]

%[1]s is TODO (text should be hard-wrapped at 80 columns).`, progname)
		le.Printf("%s\n\n%s", desc,
			pflag.CommandLine.FlagUsagesWrapped(86))
	}
	pflag.Parse()

	if pflag.NArg() > 0 {
		le.Printf("Unexpected argument: %s\n\n", strings.Join(pflag.Args(), " "))
		pflag.Usage()
		exit(2)
	}

	if helpOnly {
		pflag.Usage()
		exit(0)
	}
	if versionOnly {
		fmt.Printf("%s %s\n", progname, version)
		exit(0)
	}

	if listPortsOnly {
		n, err := printPorts()
		if err != nil {
			le.Printf("%v\n", err)
			exit(1)
		} else if n == 0 {
			exit(1)
		}
		// Successful only if we found some port
		exit(0)
	}

	if enterUSS && fileUSS != "" {
		le.Printf("Pass only one of --uss or --uss-file.\n\n")
		pflag.Usage()
		exit(2)
	}

	fido := newFido(devPath, speed, enterUSS, fileUSS, pinentry, exit)

	if testOnly {
		test(fido)
		exit(0)
	}

	softHID := newSoftHID(fido)
	err := softHID.Run(context.Background())
	if err != nil {
		le.Printf("Run failed: %s\n", err)
		exit(1)
	}

	exit(0)
}

func readBuildInfo() string {
	version := "devel without BuildInfo"
	if info, ok := debug.ReadBuildInfo(); ok {
		sb := strings.Builder{}
		sb.WriteString("devel")
		for _, setting := range info.Settings {
			if strings.HasPrefix(setting.Key, "vcs") {
				sb.WriteString(fmt.Sprintf(" %s=%s", setting.Key, setting.Value))
			}
		}
		version = sb.String()
	}
	return version
}

func printPorts() (int, error) {
	ports, err := util.GetSerialPorts()
	if err != nil {
		return 0, fmt.Errorf("Failed to list ports: %w", err)
	}
	if len(ports) == 0 {
		le.Printf("No TKey serial ports found.\n")
	} else {
		le.Printf("TKey serial ports (on stdout):\n")
		for _, p := range ports {
			fmt.Fprintf(os.Stdout, "%s serialNumber:%s\n", p.DevPath, p.SerialNumber)
		}
	}
	return len(ports), nil
}

func test(s *fido) {
	defer s.closeNow()

	appliParam := sha256.Sum256([]byte("example.com"))

	// The pubkey bytes are in uncompressed form, with marker first
	// (65 bytes total)
	fmt.Printf("Register...\n")
	userPresence, keyHandle, pubBytes, err := s.u2fRegister(appliParam)
	if err != nil {
		le.Printf("U2FRegister failed: %v\n", err)
		return
	}
	fmt.Printf("Register returned: userPresence:%v keyHandle:%0x pubBytes:%0x\n", userPresence, keyHandle, pubBytes)

	if userPresence == 0 {
		le.Printf("User not present, bailing out\n")
		return
	}

	fmt.Printf("CheckOnly...\n")
	keyHandleValid, err := s.u2fCheckOnly(appliParam, *(*[64]byte)(keyHandle))
	if err != nil {
		le.Printf("U2FCheckOnly failed: %v\n", err)
		return
	}
	fmt.Printf("CheckOnly returned: keyHandleValid:%v\n", keyHandleValid)

	if !keyHandleValid {
		le.Printf("Keyhandle not valid, bailing out\n")
		return
	}

	challParam := sha256.Sum256([]byte("håll den som en gyro"))

	checkUser := true
	counter := uint32(0)

	fmt.Printf("Authenticate...\n")
	keyHandleValid, userPresence, sigASN1, err := s.u2fAuthenticate(appliParam,
		challParam, *(*[64]byte)(keyHandle), checkUser, counter)
	if err != nil {
		le.Printf("U2FAuthenticate failed: %v\n", err)
		return
	}
	fmt.Printf("Authenticate(checkUser:%v) returned: keyHandleValid:%v userPresence:%v len(sigASN1):%d\n", checkUser, keyHandleValid, userPresence, len(sigASN1))

	if checkUser && userPresence == 0 {
		le.Printf("User presence required but user not present, bailing out\n")
		return
	}

	pubX, pubY := elliptic.Unmarshal(elliptic.P256(), pubBytes)
	if pubX == nil {
		fmt.Printf("unmarshal fail\n")
		return
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: pubX, Y: pubY}

	var signData bytes.Buffer
	signData.Write(appliParam[:])
	signData.WriteByte(userPresence)
	_ = binary.Write(&signData, binary.BigEndian, counter)
	signData.Write(challParam[:])
	hash := sha256.Sum256(signData.Bytes())

	if ecdsa.VerifyASN1(pub, hash[:], sigASN1) {
		fmt.Printf("Their signature verified!\n")
	} else {
		fmt.Printf("Their signature did NOT verify\n")
	}
}
