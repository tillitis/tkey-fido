// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

// Package tk1fido provides a connection to the fido app running on
// the TKey. You're expected to pass an existing connection to it, so
// use it like this:
//
//	tk := tk1.New()
//	err := tk.Connect(port)
//	fido := tk1fido.New(tk)
package tk1fido

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/tillitis/tkeyclient"
)

var (
	cmdGetNameVersion     = appCmd{0x01, "cmdGetNameVersion", tkeyclient.CmdLen1}
	rspGetNameVersion     = appCmd{0x02, "rspGetNameVersion", tkeyclient.CmdLen32}
	cmdU2FRegister        = appCmd{0x03, "cmdU2FRegister", tkeyclient.CmdLen128}
	rspU2FRegister        = appCmd{0x04, "rspU2FRegister", tkeyclient.CmdLen128}
	cmdU2FCheckOnly       = appCmd{0x05, "cmdU2FCheckOnly", tkeyclient.CmdLen128}
	rspU2FCheckOnly       = appCmd{0x06, "rspU2FCheckOnly", tkeyclient.CmdLen4}
	cmdU2FAuthenticateSet = appCmd{0x07, "cmdU2FAuthenticateSet", tkeyclient.CmdLen128}
	cmdU2FAuthenticateGo  = appCmd{0x08, "cmdU2FAuthenticateGo", tkeyclient.CmdLen128}
	rspU2FAuthenticate    = appCmd{0x09, "rspU2FAuthenticate", tkeyclient.CmdLen128}
)

type appCmd struct {
	code   byte
	name   string
	cmdLen tkeyclient.CmdLen
}

func (c appCmd) Code() byte {
	return c.code
}

func (c appCmd) CmdLen() tkeyclient.CmdLen {
	return c.cmdLen
}

func (c appCmd) Endpoint() tkeyclient.Endpoint {
	return tkeyclient.DestApp
}

func (c appCmd) String() string {
	return c.name
}

type Fido struct {
	tk *tkeyclient.TillitisKey // A connection to a TKey
}

// New allocates a struct for communicating with the Fido app running
// on the TKey. You're expected to pass an existing connection to it,
// so use it like this:
//
//	tk := tkeyclient.New()
//	err := tk.Connect(port)
//	fido := tkeyclientfido.New(tk)
func New(tk *tkeyclient.TillitisKey) Fido {
	var fido Fido

	fido.tk = tk

	return fido
}

// Close closes the connection to the TKey
func (f Fido) Close() error {
	if err := f.tk.Close(); err != nil {
		return fmt.Errorf("tk.Close: %w", err)
	}
	return nil
}

// GetAppNameVersion gets the name and version of the running app in
// the same style as the stick itself.
func (f Fido) GetAppNameVersion() (*tkeyclient.NameVersion, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdGetNameVersion, id)
	if err != nil {
		return nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	tkeyclient.Dump("GetAppNameVersion tx", tx)
	if err = f.tk.Write(tx); err != nil {
		return nil, fmt.Errorf("Write: %w", err)
	}

	err = f.tk.SetReadTimeout(2)
	if err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	rx, _, err := f.tk.ReadFrame(rspGetNameVersion, id)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	err = f.tk.SetReadTimeout(0)
	if err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	nameVer := &tkeyclient.NameVersion{}
	nameVer.Unpack(rx[2:])

	return nameVer, nil
}

func (f Fido) U2FRegister(appliParam [32]byte) (byte, []byte, []byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdU2FRegister, id)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	copy(tx[2:], appliParam[:])

	tkeyclient.Dump("U2FRegister tx", tx)
	if err = f.tk.Write(tx); err != nil {
		return 0, nil, nil, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := f.tk.ReadFrame(rspU2FRegister, id)
	tkeyclient.Dump("U2FRegister rx", rx)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("ReadFrame: %w", err)
	}
	// Skip over frame header and app header (cmd)
	rx = rx[2:]

	status, rx := shiftByte(rx)
	if status != tkeyclient.StatusOK {
		return 0, nil, nil, fmt.Errorf("U2FRegister NOK")
	}

	userPresence, rx := shiftByte(rx)
	keyHandle, _ := shiftBytes(rx, 64)

	// Now read 2nd response

	rx, _, err = f.tk.ReadFrame(rspU2FRegister, id)
	tkeyclient.Dump("U2FRegister rx (2nd)", rx)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("ReadFrame (2nd): %w", err)
	}
	// Skip over frame header and app header (cmd)
	rx = rx[2:]

	status, rx = shiftByte(rx)
	if status != tkeyclient.StatusOK {
		return 0, nil, nil, fmt.Errorf("U2FRegister NOK (2nd)")
	}

	pubBytes, _ := shiftBytes(rx, 64)

	// Prepending the 0x04 marker to indicate uncompressed form
	return userPresence, keyHandle, append([]byte{0x04}, pubBytes...), nil
}

func (f Fido) U2FCheckOnly(appliParam [32]byte, keyHandle [64]byte) (bool, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdU2FCheckOnly, id)
	if err != nil {
		return false, fmt.Errorf("NewFrameBuf: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(appliParam[:])
	buf.Write(keyHandle[:])
	copy(tx[2:], buf.Bytes())

	tkeyclient.Dump("U2FCheckOnly tx", tx)
	if err = f.tk.Write(tx); err != nil {
		return false, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := f.tk.ReadFrame(rspU2FCheckOnly, id)
	tkeyclient.Dump("U2FCheckOnly rx", rx)
	if err != nil {
		return false, fmt.Errorf("ReadFrame: %w", err)
	}

	// Skip over frame header and app header (cmd)
	rx = rx[2:]

	status, rx := shiftByte(rx)
	if status != tkeyclient.StatusOK {
		return false, fmt.Errorf("U2FCheckOnly NOK")
	}

	keyHandleValid, _ := shiftBool(rx)

	return keyHandleValid, nil
}

func (f Fido) U2FAuthenticate(appliParam, challParam [32]byte, keyHandle [64]byte, checkUser bool, counter uint32) (bool, byte, []byte, error) {
	// Send the 1st command with its data
	err := f.u2fAuthenticateSet(appliParam, challParam)
	if err != nil {
		return false, 0, nil, err
	}

	// Continue with the 2nd command

	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdU2FAuthenticateGo, id)
	if err != nil {
		return false, 0, nil, fmt.Errorf("NewFrameBuf: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(keyHandle[:])
	if checkUser {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	// Counter in big-endian, ready for the sig_data
	_ = binary.Write(&buf, binary.BigEndian, counter)
	copy(tx[2:], buf.Bytes())

	tkeyclient.Dump("U2FAuthenticateGo tx", tx)
	if err = f.tk.Write(tx); err != nil {
		return false, 0, nil, fmt.Errorf("Write: %w", err)
	}

	rx, _, err := f.tk.ReadFrame(rspU2FAuthenticate, id)
	tkeyclient.Dump("U2FAuthenticate rx (Go)", rx)
	if err != nil {
		return false, 0, nil, fmt.Errorf("ReadFrame: %w", err)
	}

	// Skip over frame header and app header (cmd)
	rx = rx[2:]

	status, rx := shiftByte(rx)
	if status != tkeyclient.StatusOK {
		return false, 0, nil, fmt.Errorf("U2FAuthenticate NOK")
	}

	keyHandleValid, rx := shiftBool(rx)
	userPresence, rx := shiftByte(rx)
	sigBytes, _ := shiftBytes(rx, 64)

	if !keyHandleValid {
		return keyHandleValid, userPresence, nil, nil
	}

	seq := struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(sigBytes[:32]),
		S: new(big.Int).SetBytes(sigBytes[32:]),
	}
	sigASN1, err := asn1.Marshal(seq)
	if err != nil {
		return false, 0, nil, fmt.Errorf("asn1.Marshal failed: %w", err)
	}

	return keyHandleValid, userPresence, sigASN1, nil
}

func (f Fido) u2fAuthenticateSet(appliParam, challParam [32]byte) error {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdU2FAuthenticateSet, id)
	if err != nil {
		return fmt.Errorf("NewFrameBuf: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(appliParam[:])
	buf.Write(challParam[:])
	copy(tx[2:], buf.Bytes())

	tkeyclient.Dump("U2FAuthenticateSet tx", tx)
	if err = f.tk.Write(tx); err != nil {
		return fmt.Errorf("Write: %w", err)
	}

	rx, _, err := f.tk.ReadFrame(rspU2FAuthenticate, id)
	tkeyclient.Dump("U2FAuthenticate rx (Set)", rx)
	if err != nil {
		return fmt.Errorf("ReadFrame: %w", err)
	}

	// Skip over frame header and app header (cmd)
	rx = rx[2:]

	status, _ := shiftByte(rx)
	if status != tkeyclient.StatusOK {
		return fmt.Errorf("U2FAuthenticateSet NOK")
	}

	return nil
}

func shiftByte(s []byte) (byte, []byte) {
	return s[0], s[1:]
}

func shiftBool(s []byte) (bool, []byte) {
	return s[0] != 0, s[1:]
}

func shiftBytes(s []byte, n int) ([]byte, []byte) {
	return s[:n], s[n:]
}
