package tokutil

import (
	"github.com/ijmae/tokutil/protobuf/tokenpb"
	"google.golang.org/protobuf/proto"
	"testing"
)

var mockAT = tokenpb.AccessToken{
	Iat:             1676446163,
	Exp:             1676705363,
	IsAuthenticated: 1,
	Uid:             "MWC5ARRF59",
	Username:        "0945789305",
	DisplayName:     "094****305",
	DeviceId:        "1111-2222-3333-4444-5555",
	DeviceName:      "Samsung",
	VersionCode:     20200202,
	Platform:        3,
	DtId:            999,
	SpId:            "1",
	AuthType:        "phone",
	Plans: []*tokenpb.Plan{{
		Id:                    "1",
		Name:                  "test",
		MaxDeviceLogin:        1,
		MaxDeviceStream:       1,
		ExpiredAt:             1234567,
		ContentIds:            []string{"1", "2", "3"},
		IsForceMaxDeviceLogin: 0,
		Platforms:             []int32{1, 2, 3},
		KplusId:               "kplusid",
		DeviceId:              "abc",
		IsAutoRenew:           0,
	}, {
		Id:                    "2",
		Name:                  "test",
		MaxDeviceLogin:        1,
		MaxDeviceStream:       1,
		ExpiredAt:             1234567,
		ContentIds:            []string{"1", "2", "3"},
		IsForceMaxDeviceLogin: 0,
		Platforms:             []int32{1, 2, 3},
		KplusId:               "kplusid",
		DeviceId:              "abc",
		IsAutoRenew:           0,
	}},
	ClientId:        "000000002477",
	HasPackage:      1,
	IsPaid:          1,
	Ip:              "113.190.233.178",
	IsFromVN:        1,
	City:            "Viet Nam_Ha Noi_Hanoi",
	Zone:            1,
	Isp:             "vnpt.com.vn",
	Jti:             "167644616345584",
	DeviceInfo:      "",
	UserAgent:       "",
	UserCollections: []string{},
	OsVersion:       "",
	AppVersion:      "",
}

var secret = "Bof"

var mockEncoded = "CNOTsp8GENP8wZ8GGAEiCk1XQzVBUlJGNTkqCjA5NDU3ODkzMDUyGDExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NToHU2Ftc3VuZ0CK9tAJSANg5wdqATFyBXBob25lei0KATESBHRlc3QYASABKIetSzIBMTIBMjIBM0IDAQIDSgdrcGx1c2lkUgNhYmN6LQoBMhIEdGVzdBgBIAEoh61LMgExMgEyMgEzQgMBAgNKB2twbHVzaWRSA2FiY4IBDDAwMDAwMDAwMjQ3N4gBAZABAZoBDzExMy4xOTAuMjMzLjE3OKABAaoBFVZpZXQgTmFtX0hhIE5vaV9IYW5vabABAboBC3ZucHQuY29tLnZuygEPMTY3NjQ0NjE2MzQ1NTg04gEKMDk0KioqKjMwNQ"

var mockSign = "CNOTsp8GENP8wZ8GGAEiCk1XQzVBUlJGNTkqCjA5NDU3ODkzMDUyGDExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NToHU2Ftc3VuZ0CK9tAJSANg5wdqATFyBXBob25lei0KATESBHRlc3QYASABKIetSzIBMTIBMjIBM0IDAQIDSgdrcGx1c2lkUgNhYmN6LQoBMhIEdGVzdBgBIAEoh61LMgExMgEyMgEzQgMBAgNKB2twbHVzaWRSA2FiY4IBDDAwMDAwMDAwMjQ3N4gBAZABAZoBDzExMy4xOTAuMjMzLjE3OKABAaoBFVZpZXQgTmFtX0hhIE5vaV9IYW5vabABAboBC3ZucHQuY29tLnZuygEPMTY3NjQ0NjE2MzQ1NTg04gEKMDk0KioqKjMwNQ.-mZlSY-MYo1llO0u2TurS2u8IxCKXyND8y0bLsqShns"

func TestEncodeAT(t *testing.T) {
	encoded, err := EncodeAT(&mockAT)

	if err != nil {
		t.Fatalf("encode fail: %v", err)
	}

	if encoded != mockEncoded {
		t.Fatalf("encode fail")
	}
}

func TestDecodeAT(t *testing.T) {
	decoded, err := DecodeAT(mockEncoded)

	if err != nil {
		t.Fatalf("decoded fail: %v", err)
	}

	if !proto.Equal(&decoded, &mockAT) {
		t.Fatalf("decoded fail")
	}
}

func TestSignAT(t *testing.T) {
	signed, err := SignAT(mockAT, secret)

	if err != nil {
		t.Fatalf("sign fail: %v", err)
	}

	if signed != mockSign {
		t.Fatalf("sign fail")
	}
}

func TestVerifyAT(t *testing.T) {
	signed, err := VerifyAT(mockSign, secret)

	if err != nil {
		t.Fatalf("verify fail: %v", err)
	}

	if !proto.Equal(&signed, &mockAT) {
		t.Fatalf("verify fail")
	}
}
