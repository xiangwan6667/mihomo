package convert_test

import (
	"encoding/json"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"net/url"
	"strings"
	"testing"
)

func TestRealityShareImportPreservesVerificationOptions(t *testing.T) {
	const publicKey = "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"
	verifyKey := strings.Repeat("A", 2603)
	for _, scheme := range []string{"vless", "vmess", "trojan"} {
		t.Run(scheme, func(t *testing.T) {
			link := scheme + "://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&type=tcp&fp=chrome&pbk=" + publicKey + "&sid=00010203&pqv=" + verifyKey + "&client-version=26.10.31&support-x25519mlkem768=false"
			proxies, err := convert.ConvertsV2Ray([]byte(link))
			if err != nil || len(proxies) != 1 {
				t.Fatalf("import failed: %v", err)
			}
			options := proxies[0]["reality-opts"].(map[string]any)
			if options["public-key"] != publicKey || options["short-id"] != "00010203" || options["mldsa65-verify"] != verifyKey || options["client-version"] != "26.10.31" || options["support-x25519mlkem768"] != false {
				t.Fatal("REALITY options lost")
			}
			if _, err := adapter.ParseProxy(proxies[0]); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestXHTTPDownloadRealityImportPreservesXrayFields(t *testing.T) {
	const publicKey = "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw"
	verifyKey := strings.Repeat("A", 2603)
	extra, _ := json.Marshal(map[string]any{"downloadSettings": map[string]any{"address": "download.example.com", "port": 443, "security": "reality", "realitySettings": map[string]any{"publicKey": "old", "password": publicKey, "shortId": "00010203", "mldsa65Verify": verifyKey, "serverName": "example.com", "fingerprint": "chrome"}}})
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=xhttp&security=tls&extra=" + url.QueryEscape(string(extra))
	proxies, err := convert.ConvertsV2Ray([]byte(link))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("import failed: %v", err)
	}
	ds := proxies[0]["xhttp-opts"].(map[string]any)["download-settings"].(map[string]any)
	opts := ds["reality-opts"].(map[string]any)
	if opts["public-key"] != publicKey || opts["mldsa65-verify"] != verifyKey || opts["short-id"] != "00010203" || ds["servername"] != "example.com" || ds["client-fingerprint"] != "chrome" {
		t.Fatal("download REALITY fields lost")
	}
	if _, err := adapter.ParseProxy(proxies[0]); err != nil {
		t.Fatal(err)
	}
}

func TestTrojanHTTPUpgradeImportPreservesPathAndHost(t *testing.T) {
	proxies, err := convert.ConvertsV2Ray([]byte("trojan://test-password@example.com:443?type=httpupgrade&path=%2Fedge&host=cdn.example.com"))
	if err != nil || len(proxies) != 1 {
		t.Fatal(err)
	}
	options := proxies[0]["ws-opts"].(map[string]any)
	if proxies[0]["network"] != "ws" || options["path"] != "/edge" || options["v2ray-http-upgrade"] != true || options["headers"].(map[string]any)["Host"] != "cdn.example.com" {
		t.Fatal("HTTPUpgrade options lost")
	}
}

func TestRealityShareRejectsMissingPublicKey(t *testing.T) {
	for _, scheme := range []string{"vless", "vmess", "trojan"} {
		for _, query := range []string{"security=reality", "pqv=test-verification-key", "client-version=26.10.31"} {
			proxies, err := convert.ConvertsV2Ray([]byte(scheme + "://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?" + query))
			if err == nil && len(proxies) != 0 {
				t.Fatalf("%s silently discarded REALITY verification", scheme)
			}
		}
	}
}

func TestVShareAliasesPreserveTransportOptions(t *testing.T) {
	for _, tc := range []struct{ alias, network, options string }{
		{"raw", "http", "http-opts"},
		{"websocket", "ws", "ws-opts"},
		{"splithttp", "xhttp", "xhttp-opts"},
	} {
		link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=" + tc.alias + "&headerType=http&path=%2Fedge&host=cdn.example.com&mode=auto&extra=%7B%22xPaddingBytes%22%3A%2230-80%22%7D"
		proxies, err := convert.ConvertsV2Ray([]byte(link))
		if err != nil || len(proxies) != 1 {
			t.Fatal(err)
		}
		options, ok := proxies[0][tc.options].(map[string]any)
		if !ok || proxies[0]["network"] != tc.network {
			t.Fatalf("%s lost transport settings", tc.alias)
		}
		if tc.network == "http" {
			if options["path"].([]string)[0] != "/edge" || options["headers"].(map[string]any)["Host"].([]string)[0] != "cdn.example.com" {
				t.Fatal("HTTP settings lost")
			}
		} else if options["path"] != "/edge" {
			t.Fatal("transport path lost")
		}
		if tc.network == "xhttp" && (options["host"] != "cdn.example.com" || options["mode"] != "auto" || options["x-padding-bytes"] != "30-80") {
			t.Fatal("XHTTP host/mode/extra lost")
		}
	}
}
