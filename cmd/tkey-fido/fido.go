// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/elliptic"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/tillitis/tillitis-key1-apps/internal/tk1fido"
	"github.com/tillitis/tillitis-key1-apps/internal/util"
	"github.com/tillitis/tillitis-key1-apps/tk1"
)

// nolint:typecheck // Avoid lint error when the embedding file is missing.
// Makefile copies the built app here ./app.bin
//
//go:embed app.bin
var appBinary []byte

var notify = func(msg string) {
	util.Notify(progname, msg)
}

const (
	idleDisconnect = 3 * time.Second
	// 4 chars each.
	wantFWName0  = "tk1 "
	wantFWName1  = "mkdf"
	wantAppName0 = "tk1 "
	wantAppName1 = "fido"
)

// TODO this should really be an exported struct (with members still
// unexported) in a different pkg
type fido struct {
	tk              *tk1.TillitisKey
	tkFido          *tk1fido.Fido
	devPath         string
	speed           int
	enterUSS        bool
	fileUSS         string
	mu              sync.Mutex
	pinentry        string
	connected       bool
	disconnectTimer *time.Timer
}

func newFido(devPathArg string, speedArg int, enterUSS bool, fileUSS string, pinentry string, exitFunc func(int)) *fido {
	tk1.SilenceLogging()

	tk := tk1.New()

	tkFido := tk1fido.New(tk)
	s := &fido{
		tk:       tk,
		tkFido:   &tkFido,
		devPath:  devPathArg,
		speed:    speedArg,
		enterUSS: enterUSS,
		fileUSS:  fileUSS,
		pinentry: pinentry,
	}

	// Do nothing on HUP, in case old udev rule is still in effect
	handleSignals(func() {}, syscall.SIGHUP)

	// Start handling signals here to catch abort during USS entering
	handleSignals(func() {
		s.closeNow()
		exitFunc(1)
	}, os.Interrupt, syscall.SIGTERM)

	return s
}

func (s *fido) connect() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.disconnectTimer != nil {
		s.disconnectTimer.Stop()
		s.disconnectTimer = nil
	}

	if s.connected {
		return true
	}

	devPath := s.devPath
	if devPath == "" {
		var err error
		devPath, err = util.DetectSerialPort(false)
		if err != nil {
			switch {
			case errors.Is(err, util.ErrNoDevice):
				notify("Could not find any TKey plugged in.")
			case errors.Is(err, util.ErrManyDevices):
				notify("Cannot work with more than 1 TKey plugged in.")
			default:
				notify(fmt.Sprintf("TKey detection failed: %s\n", err))
			}
			le.Printf("Failed to detect port: %v\n", err)
			return false
		}
		le.Printf("Auto-detected serial port %s\n", devPath)
	}

	le.Printf("Connecting to TKey on serial port %s\n", devPath)
	if err := s.tk.Connect(devPath, tk1.WithSpeed(s.speed)); err != nil {
		notify(fmt.Sprintf("Failed to connect to a TKey on port %v.", devPath))
		le.Printf("Failed to connect: %v", err)
		return false
	}

	if s.isFirmwareMode() {
		le.Printf("The TKey is in firmware mode.\n")
		if err := s.loadApp(); err != nil {
			le.Printf("Failed to load app: %v\n", err)
			s.closeNow()
			return false
		}
	}

	if !s.isWantedApp() {
		// Notifying because we're kinda stuck if we end up here
		notify("Please remove and plug in your TKey again\n— it might be running the wrong app.")
		le.Printf("No TKey on the serial port, or it's running wrong app (and is not in firmware mode)")
		s.closeNow()
		return false
	}

	// We nowadays disconnect from the TKey when idling, so the
	// fido-app that's running may have been loaded by somebody else.
	// Therefore we can never be sure it has USS according to the
	// flags that tkey-ssh-agent was started with. So we no longer say
	// anything about that.

	s.connected = true
	return true
}

func (s *fido) isFirmwareMode() bool {
	nameVer, err := s.tk.GetNameVersion()
	if err != nil {
		return false
	}
	// not caring about nameVer.Version
	return nameVer.Name0 == wantFWName0 &&
		nameVer.Name1 == wantFWName1
}

func (s *fido) isWantedApp() bool {
	nameVer, err := s.tkFido.GetAppNameVersion()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			le.Printf("GetAppNameVersion: %s\n", err)
		}
		return false
	}
	// not caring about nameVer.Version
	return nameVer.Name0 == wantAppName0 &&
		nameVer.Name1 == wantAppName1
}

func (s *fido) loadApp() error {
	var secret []byte
	if s.enterUSS {
		udi, err := s.tk.GetUDI()
		if err != nil {
			return fmt.Errorf("Failed to get UDI: %w", err)
		}

		secret, err = getSecret(udi.String(), s.pinentry)
		if err != nil {
			return fmt.Errorf("Failed to get USS: %w", err)
		}
	} else if s.fileUSS != "" {
		var err error
		secret, err = util.ReadUSS(s.fileUSS)
		if err != nil {
			return fmt.Errorf("Failed to read uss-file %s: %w", s.fileUSS, err)
		}
	}

	le.Printf("Loading fido app...\n")
	if err := s.tk.LoadApp(appBinary, secret); err != nil {
		return fmt.Errorf("LoadApp: %w", err)
	}
	le.Printf("Fido app loaded.\n")

	return nil
}

func (s *fido) disconnect() {
	if s.tkFido == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.connected {
		return
	}

	if s.disconnectTimer != nil {
		s.disconnectTimer.Stop()
		s.disconnectTimer = nil
	}

	s.disconnectTimer = time.AfterFunc(idleDisconnect, func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.closeNow()
		s.connected = false
		s.disconnectTimer = nil
		le.Printf("Disconnected from TKey\n")
	})
}

func (s *fido) closeNow() {
	if s.tkFido == nil {
		return
	}
	if err := s.tkFido.Close(); err != nil {
		le.Printf("Close failed: %s\n", err)
	}
}

func (s *fido) u2fRegister(appliParam [32]byte) (byte, []byte, []byte, error) {
	if !s.connect() {
		return 0, nil, nil, fmt.Errorf("Connect failed")
	}
	defer s.disconnect()

	// Keyhandle is 64 bytes long, pubkey is in uncompressed form with
	// 0x04 marker first, 65 bytes
	userPresence, keyHandle, pubBytes, err := s.tkFido.U2FRegister(appliParam)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("U2FRegister: %w", err)
	}

	if userPresence == 0 {
		return userPresence, nil, nil, nil
	}

	pubX, _ := elliptic.Unmarshal(elliptic.P256(), pubBytes)
	if pubX == nil {
		return 0, nil, nil, fmt.Errorf("Failed to unmarshal pubkey bytes")
	}

	return userPresence, keyHandle, pubBytes, nil
}

func (s *fido) u2fCheckOnly(appliParam [32]byte, keyHandle [64]byte) (bool, error) {
	if !s.connect() {
		return false, fmt.Errorf("Connect failed")
	}
	defer s.disconnect()

	keyHandleValid, err := s.tkFido.U2FCheckOnly(appliParam, keyHandle)
	if err != nil {
		return false, fmt.Errorf("U2FCheckOnly: %w", err)
	}

	return keyHandleValid, nil
}

func (s *fido) u2fAuthenticate(appliParam, challParam [32]byte, keyHandle [64]byte, checkUser bool, counter uint32) (bool, byte, []byte, error) {
	if !s.connect() {
		return false, 0, nil, fmt.Errorf("Connect failed")
	}
	defer s.disconnect()

	// Sig is in DER ASN1 format (ANSI X9.62), should be 71-73 bytes
	// (or is it 70-73 bytes?)
	keyHandleValid, userPresence, sigASN1, err := s.tkFido.U2FAuthenticate(appliParam,
		challParam, keyHandle, checkUser, counter)
	if err != nil {
		return false, 0, nil, fmt.Errorf("U2FAuthenticate: %w", err)
	}

	return keyHandleValid, userPresence, sigASN1, nil
}

func handleSignals(action func(), sig ...os.Signal) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig...)
	go func() {
		for {
			<-ch
			action()
		}
	}()
}
