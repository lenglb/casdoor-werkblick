// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenerateRsaKeys(t *testing.T) {
	certificate, privateKey, err := generateRsaKeys(2048, 512, 20, "Casdoor Cert", "Casdoor Organization")
	if err != nil {
		t.Fatal(err)
	}
	assertGeneratedKeyPair(t, certificate, privateKey)
}

func TestGenerateEsKeys(t *testing.T) {
	certificate, privateKey, err := generateEsKeys(256, 20, "Casdoor Cert", "Casdoor Organization")
	if err != nil {
		t.Fatal(err)
	}
	assertGeneratedKeyPair(t, certificate, privateKey)
}

func TestGenerateRsaPssKeys(t *testing.T) {
	certificate, privateKey, err := generateRsaPssKeys(2048, 256, 20, "Casdoor Cert", "Casdoor Organization")
	if err != nil {
		t.Fatal(err)
	}
	assertGeneratedKeyPair(t, certificate, privateKey)
}

func TestGeneratedSigningKeysAreUnique(t *testing.T) {
	certificate1, privateKey1, err := generateRsaKeys(2048, 256, 20, "cert-built-in", "admin")
	if err != nil {
		t.Fatal(err)
	}
	certificate2, privateKey2, err := generateRsaKeys(2048, 256, 20, "cert-built-in", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if certificate1 == certificate2 || privateKey1 == privateKey2 {
		t.Fatal("fresh installations received identical signing material")
	}

	cert1 := parseGeneratedCertificate(t, certificate1)
	cert2 := parseGeneratedCertificate(t, certificate2)
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Fatal("fresh certificates received the same random serial number")
	}
}

func assertGeneratedKeyPair(t *testing.T, certificate string, privateKey string) {
	t.Helper()
	if _, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey)); err != nil {
		t.Fatalf("generated certificate/key pair is invalid: %v", err)
	}
	cert := parseGeneratedCertificate(t, certificate)
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		t.Fatalf("generated certificate serial is invalid: %v", cert.SerialNumber)
	}
}

func parseGeneratedCertificate(t *testing.T, certificate string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("generated certificate is not PEM encoded")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
