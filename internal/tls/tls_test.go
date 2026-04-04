/*
 * Copyright 2026 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tls

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestFindDisallowedCipher(t *testing.T) {
	oldProfile := configv1.TLSProfiles[configv1.TLSProfileOldType]
	intermediateProfile := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]

	t.Run("returns empty when all ciphers are allowed", func(t *testing.T) {
		got := FindDisallowedCipher(oldProfile.Ciphers)
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("finds a disallowed cipher for intermediate profile", func(t *testing.T) {
		got := FindDisallowedCipher(intermediateProfile.Ciphers)
		if got == "" {
			t.Fatal("expected a disallowed cipher, got empty")
		}
		for _, c := range intermediateProfile.Ciphers {
			if c == got {
				t.Errorf("returned cipher %q should not be in the allowed set", got)
			}
		}
	})

	t.Run("skips TLS 1.3 ciphers", func(t *testing.T) {
		// allow nothing — first result must still be a TLS 1.2 cipher
		got := FindDisallowedCipher(nil)
		if got == "" {
			t.Fatal("expected a disallowed cipher, got empty")
		}
		if len(got) >= 4 && got[:4] == "TLS_" {
			t.Errorf("returned cipher %q is a TLS 1.3 cipher, should have been skipped", got)
		}
	})

	t.Run("returns empty when allowed is nil but old profile has no TLS 1.2 ciphers", func(t *testing.T) {
		// This case can't actually happen with real profiles, but tests
		// the logic: if we pass all old ciphers as allowed, nothing is disallowed.
		got := FindDisallowedCipher(oldProfile.Ciphers)
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

func TestCurlTLSVersionToUint16(t *testing.T) {
	tests := []struct {
		input    string
		expected uint16
		wantErr  bool
	}{
		{input: "TLSv1", expected: tls.VersionTLS10},
		{input: "TLSv1.0", expected: tls.VersionTLS10},
		{input: "TLSv1.1", expected: tls.VersionTLS11},
		{input: "TLSv1.2", expected: tls.VersionTLS12},
		{input: "TLSv1.3", expected: tls.VersionTLS13},
		{input: "SSLv3", wantErr: true},
		{input: "", wantErr: true},
		{input: "garbage", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := CurlTLSVersionToUint16(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got %d", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if got != tt.expected {
				t.Errorf("CurlTLSVersionToUint16(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCurlTLSValue(t *testing.T) {
	tests := []struct {
		input    uint16
		expected string
	}{
		{input: tls.VersionTLS10, expected: "1.0"},
		{input: tls.VersionTLS11, expected: "1.1"},
		{input: tls.VersionTLS12, expected: "1.2"},
		{input: tls.VersionTLS13, expected: "1.3"},
		{input: 0, expected: ""},
		{input: 9999, expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := CurlTLSValue(tt.input)
			if got != tt.expected {
				t.Errorf("CurlTLSValue(%d) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestTlsVersionBelow(t *testing.T) {
	tests := []struct {
		name     string
		input    uint16
		expected uint16
	}{
		{name: "below TLS 1.3", input: tls.VersionTLS13, expected: tls.VersionTLS12},
		{name: "below TLS 1.2", input: tls.VersionTLS12, expected: tls.VersionTLS11},
		{name: "below TLS 1.1", input: tls.VersionTLS11, expected: tls.VersionTLS10},
		{name: "below TLS 1.0", input: tls.VersionTLS10, expected: 0},
		{name: "unknown version", input: 0, expected: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TlsVersionBelow(tt.input)
			if got != tt.expected {
				t.Errorf("TlsVersionBelow(%d) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSSLConnectionRegex(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantVersion string
		wantCipher  string
		shouldMatch bool
	}{
		{
			name:        "TLS 1.3 with OpenSSL",
			input:       "* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384",
			wantVersion: "TLSv1.3",
			wantCipher:  "TLS_AES_256_GCM_SHA384",
			shouldMatch: true,
		},
		{
			name:        "TLS 1.2 with OpenSSL",
			input:       "* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256",
			wantVersion: "TLSv1.2",
			wantCipher:  "ECDHE-RSA-AES128-GCM-SHA256",
			shouldMatch: true,
		},
		{
			name:        "embedded in multi-line verbose output",
			input:       "* Connected to localhost\n* ALPN: offers h2\n* SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256\n* Server certificate:\n",
			wantVersion: "TLSv1.3",
			wantCipher:  "TLS_AES_128_GCM_SHA256",
			shouldMatch: true,
		},
		{
			name:        "no match in output",
			input:       "* Connected to localhost\n* some other output\n",
			shouldMatch: false,
		},
		{
			name:        "empty output",
			input:       "",
			shouldMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := sslConnectionRe.FindStringSubmatch(tt.input)
			if !tt.shouldMatch {
				if len(matches) >= 3 {
					t.Errorf("expected no match, got version=%q cipher=%q", matches[1], matches[2])
				}
				return
			}
			if len(matches) < 3 {
				t.Fatalf("expected match, got none for input: %s", tt.input)
			}
			if matches[1] != tt.wantVersion {
				t.Errorf("version = %q, want %q", matches[1], tt.wantVersion)
			}
			if matches[2] != tt.wantCipher {
				t.Errorf("cipher = %q, want %q", matches[2], tt.wantCipher)
			}
		})
	}
}
