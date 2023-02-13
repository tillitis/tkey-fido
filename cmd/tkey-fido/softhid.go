// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

// NOTE: This is based on
// https://github.com/psanford/ctapkey/blob/main/ctapkey.go But we
// want to for example to deal with user presence in the program
// running on our TKey (physical touch), not in the "softHID".

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/psanford/ctapkey/attestation"
	"github.com/psanford/ctapkey/fidohid"
	"github.com/psanford/ctapkey/sitesignatures"
	"github.com/psanford/ctapkey/statuscode"
	"github.com/psanford/ctapkey/u2f"
)

// NOTES
//
// We have a timeout (currently 10s) when checking for user presence
// (touch). On registration this is always done. On authentication we
// only do it if required (enforce-user-presence). But at least the
// yubico demo site just tries again when it gets user-presence==0. Or
// is it the FIDO client (browser) that retries?
// https://demo.yubico.com/webauthn-technical/registration

// Reference documents:
//
// SPEC-U2F: https://web.archive.org/web/20221120085005/https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html

const uhidName = "tkey-hid"

type softHID struct {
	theFido     *fido
	operationMu sync.Mutex // only handling 1 HID message at a time
}

func newSoftHID(s *fido) *softHID {
	return &softHID{theFido: s}
}

func (s *softHID) Run(ctx context.Context) error {
	token, err := fidohid.New(ctx, uhidName, fidohid.WithCTAP2Disabled())
	if err != nil {
		return fmt.Errorf("fidohid.New: %w", err)
	}

	go token.Run(ctx)
	le.Printf("Running soft HID...\n")

	for ev := range token.Events() {
		if ev.Error != nil {
			le.Printf("token event error: %s", err)
			continue
		}

		req, err := u2f.DecodeAuthenticatorRequest(ev.Msg)
		if err != nil {
			le.Printf("DecodeAuthenticatorRequest failed: %s", err)
			continue
		}

		switch req.Command {
		case u2f.CmdVersion:
			le.Printf("cmd: version")
			if err := token.WriteResponse(ctx, ev, []byte("U2F_V2"), statuscode.NoError); err != nil {
				le.Printf("WriteResponse failed: %s\n", err)
			}
		case u2f.CmdRegister:
			le.Printf("cmd: register site=%s", sitesignatures.FromAppParam(req.Register.ApplicationParam))
			if err := s.handleRegister(ctx, token, ev, req); err != nil {
				le.Printf("handleRegister error: %s\n", err)
			}
		case u2f.CmdAuthenticate:
			le.Printf("cmd: authenticate site=%s ctrl=%s", sitesignatures.FromAppParam(req.Authenticate.ApplicationParam),
				authCtrlString(req.Authenticate.Ctrl))
			if err := s.handleAuthenticate(ctx, token, ev, req); err != nil {
				le.Printf("handleAuthenticate error: %s\n", err)
			}
		default:
			le.Printf("unsupported cmd: 0x%02x\n", req.Command)
			// send a not supported error for any commands that we
			// don't understand. Browsers depend on this to detect
			// what features the token supports (i.e. the u2f
			// backwards compatibility)
			if err := token.WriteResponse(ctx, ev, nil, statuscode.ClaNotSupported); err != nil {
				le.Printf("WriteResponse failed: %s\n", err)
			}
		}
	}

	return fmt.Errorf("ctx.Err: %w", ctx.Err())
}

func (s *softHID) handleRegister(ctx context.Context, token *fidohid.SoftToken, ev fidohid.HIDEvent, req *u2f.AuthenticatorRequest) error {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()

	userPresence, keyHandle, pubBytes, err := s.theFido.u2fRegister(req.Register.ApplicationParam)
	if err != nil {
		return fmt.Errorf("u2fRegister failed: %w", err)
	}

	if userPresence == 0 {
		le.Printf("register: no user present\n")
		if err = token.WriteResponse(ctx, ev, nil, statuscode.ConditionsNotSatisfied); err != nil {
			le.Printf("WriteResponse failed: %s\n", err)
		}
		return nil
	}

	// TODO We're doing attestation signing here in the host-program
	// just like tpm-fido, and using the same "dummy"
	// certificate/privatekey as they.
	var attSigData bytes.Buffer
	attSigData.WriteByte(0x00) // reserved byte
	attSigData.Write(req.Register.ApplicationParam[:])
	attSigData.Write(req.Register.ChallengeParam[:])
	attSigData.Write(keyHandle)
	attSigData.Write(pubBytes)
	hash := sha256.Sum256(attSigData.Bytes())

	attSig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, hash[:])
	if err != nil {
		return fmt.Errorf("SignASN1 (attestation) failed: %w", err)
	}

	var resp bytes.Buffer
	resp.WriteByte(0x05) // reserved byte
	resp.Write(pubBytes)
	resp.WriteByte(byte(len(keyHandle)))
	resp.Write(keyHandle)
	// btw, this cert has: Not After : Jul 24 20:09:08 2027 GMT
	resp.Write(attestation.CertDer)
	resp.Write(attSig)

	le.Printf("register: success\n")
	if err = token.WriteResponse(ctx, ev, resp.Bytes(), statuscode.NoError); err != nil {
		le.Printf("WriteResponse failed: %s\n", err)
	}
	return nil
}

func (s *softHID) handleAuthenticate(ctx context.Context, token *fidohid.SoftToken, ev fidohid.HIDEvent, req *u2f.AuthenticatorRequest) error {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()

	// Our keyhandles are always 64 bytes
	if l := len(req.Authenticate.KeyHandle); l != 64 {
		if err := token.WriteResponse(ctx, ev, nil, statuscode.WrongData); err != nil {
			le.Printf("WriteResponse failed: %s\n", err)
		}
		return fmt.Errorf("input keyhandle length was %d (expected %d)", l, 64)
	}

	keyHandle := *(*[64]byte)(req.Authenticate.KeyHandle)
	appliParam := req.Authenticate.ApplicationParam

	keyHandleValid, err := s.theFido.u2fCheckOnly(appliParam, keyHandle)
	if err != nil {
		if err2 := token.WriteResponse(ctx, ev, nil, statuscode.WrongData); err2 != nil {
			le.Printf("WriteResponse failed: %s\n", err2)
		}
		return fmt.Errorf("u2fCheckOnly failed: %w", err)
	} else if !keyHandleValid {
		le.Printf("authenticate: checkonly, keyhandle not valid: %0x\n", keyHandle)
		if err = token.WriteResponse(ctx, ev, nil, statuscode.WrongData); err != nil {
			le.Printf("WriteResponse failed: %s\n", err)
		}
		return nil
	}

	// If we're only asked to check the keyhandle then we're done now
	if req.Authenticate.Ctrl == u2f.CtrlCheckOnly {
		le.Printf("authenticate: checkonly success\n")
		// This is according to 5.1 in [SPEC-U2F]. When doing
		// "check-only" and the keyhandle was indeed created by this
		// token: "the U2F token MUST respond with an authentication
		// response message:error:test-of-user-presence-required (note
		// that despite the name this signals a success condition)."
		if err = token.WriteResponse(ctx, ev, nil, statuscode.ConditionsNotSatisfied); err != nil {
			le.Printf("WriteResponse failed: %s\n", err)
		}
		return nil
	}

	checkUser := (req.Authenticate.Ctrl == u2f.CtrlEnforeUserPresenceAndSign)
	// TODO hardcoded. Here we should read counter from some storage
	// in user's homedir, increment it, write it back
	counter := uint32(1)

	keyHandleValid, userPresence, sigASN1, err := s.theFido.u2fAuthenticate(appliParam,
		req.Authenticate.ChallengeParam, keyHandle, checkUser, counter)
	if err != nil {
		if err2 := token.WriteResponse(ctx, ev, nil, statuscode.WrongData); err2 != nil {
			le.Printf("WriteResponse failed: %s\n", err2)
		}
		return fmt.Errorf("u2fAuthenticate failed: %w", err)
	} else if !keyHandleValid {
		le.Printf("authenticate: NOT checkonly, keyhandle not valid: %0x\n", keyHandle)
		if err = token.WriteResponse(ctx, ev, nil, statuscode.WrongData); err != nil {
			le.Printf("WriteResponse failed: %s\n", err)
		}
		return nil
	}

	if checkUser && userPresence == 0 {
		le.Printf("authenticate: user not present but required\n")
		if err = token.WriteResponse(ctx, ev, nil, statuscode.ConditionsNotSatisfied); err != nil {
			le.Printf("WriteResponse failed: %s\n", err)
		}
		return nil
	}

	var resp bytes.Buffer
	resp.WriteByte(userPresence)
	_ = binary.Write(&resp, binary.BigEndian, counter)
	resp.Write(sigASN1)

	le.Printf("authenticate: success\n")
	if err = token.WriteResponse(ctx, ev, resp.Bytes(), statuscode.NoError); err != nil {
		le.Printf("WriteResponse failed: %s\n", err)
	}
	return nil
}

func authCtrlString(authCtrl u2f.AuthCtrl) string {
	switch authCtrl {
	case u2f.CtrlCheckOnly:
		return "check-only"
	case u2f.CtrlEnforeUserPresenceAndSign:
		return "enforce-user-presence"
	case u2f.CtrlDontEnforeUserPresenceAndSign:
		return "dont-enforce-user-presence"
	default:
		return "unknown"
	}
}
