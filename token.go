package tokutil

import (
	"crypto/hmac"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	tokenpb "github.com/ijmae/tokutil/protobuf/tokenpb"
	jsoniter "github.com/json-iterator/go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func encode(decoded protoreflect.ProtoMessage) (string, error) {
	out, err := proto.Marshal(decoded)

	if err != nil {
		return "", err
	}

	return b64.RawURLEncoding.EncodeToString([]byte(out)), nil
}

func EncodeAT(decoded *tokenpb.AccessToken) (string, error) {
	out, err := encode(decoded)

	if err != nil {
		return "", err
	}

	return out, nil
}

func EncodeRT(decoded *tokenpb.RefreshToken) (string, error) {
	out, err := encode(decoded)

	if err != nil {
		return "", err
	}

	return out, nil
}

func decode(encodedBase64URL string, data protoreflect.ProtoMessage) error {
	decodedBase64URL, errDecodeBase64 := b64.RawURLEncoding.DecodeString(encodedBase64URL)

	if errDecodeBase64 != nil {
		return errDecodeBase64
	}

	errDecodeProto := proto.Unmarshal([]byte(decodedBase64URL), data)

	if errDecodeProto != nil {
		return errDecodeProto
	}

	return nil
}

func DecodeAT(encodedBase64URL string) (tokenpb.AccessToken, error) {
	var at tokenpb.AccessToken

	if err := decode(encodedBase64URL, &at); err != nil {
		return at, err
	}

	return at, nil
}

func DecodeRT(encodedBase64URL string) (tokenpb.RefreshToken, error) {
	var rt tokenpb.RefreshToken

	if err := decode(encodedBase64URL, &rt); err != nil {
		return rt, err
	}

	return rt, nil
}

func DecodeATToJSON(encodedBase64URL string) (string, error) {
	var at tokenpb.AccessToken

	if err := decode(encodedBase64URL, &at); err != nil {
		return "", err
	}

	json, errToJSON := json.Marshal(at)

	if errToJSON != nil {
		return "", errToJSON
	}

	return string(json), nil
}

func DecodeRToJSON(encodedBase64URL string) (string, error) {
	var rt tokenpb.RefreshToken

	if err := decode(encodedBase64URL, &rt); err != nil {
		return "", err
	}

	json, errToJSON := json.Marshal(rt)

	if errToJSON != nil {
		return "", errToJSON
	}

	return string(json), nil
}

func doHMAC(input, secret, outType string) (string, error) {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	_, err := h.Write([]byte(input))

	if err != nil {
		return "", err
	}

	// Convert to []byte
	b := h.Sum(nil)

	if outType == "base64" {
		return b64.RawStdEncoding.EncodeToString(b), nil
	}

	if outType == "base64URL" {
		return b64.RawURLEncoding.EncodeToString(b), nil
	}

	return hex.EncodeToString(b), nil

}

func SignAT(payload tokenpb.AccessToken, secret string) (string, error) {

	encodedAT, err := EncodeAT(&payload)

	if err != nil {
		return "", err
	}

	signedAT, err := doHMAC(encodedAT, secret, "base64URL")

	if err != nil {
		return "", err
	}

	var s strings.Builder

	s.WriteString(encodedAT)
	s.WriteString(".")
	s.WriteString(signedAT)

	return s.String(), nil
}

func SignRT(payload tokenpb.RefreshToken, secret string) (string, error) {

	encodedAT, err := EncodeRT(&payload)

	if err != nil {
		return "", err
	}

	signedAT, err := doHMAC(encodedAT, secret, "base64URL")

	if err != nil {
		return "", err
	}

	var s strings.Builder

	s.WriteString(encodedAT)
	s.WriteString(".")
	s.WriteString(signedAT)

	return s.String(), nil
}

func VerifyAT(token, secret string) (tokenpb.AccessToken, error) {

	var at tokenpb.AccessToken

	tokenArr := strings.Split(token, ".")

	if len(tokenArr) < 2 {
		return at, errors.New("invalid token")
	}

	payload := tokenArr[0]

	signed := tokenArr[1]

	signedVerify, err := doHMAC(payload, secret, "base64URL")

	if err != nil {
		return at, err
	}

	if signedVerify != signed {
		return tokenpb.AccessToken{}, errors.New("invalid token")
	}

	at, errDecode := DecodeAT(payload)

	if errDecode != nil {
		return tokenpb.AccessToken{}, errDecode
	}

	if int64(at.Exp) < time.Now().Unix() {
		return tokenpb.AccessToken{}, errors.New("expired token")
	}

	return at, nil
}

func VerifyRT(token, secret string) (tokenpb.RefreshToken, error) {

	var rt tokenpb.RefreshToken

	tokenArr := strings.Split(token, ".")

	payload := tokenArr[0]

	signed := tokenArr[1]

	signedVerify, err := doHMAC(payload, secret, "base64URL")

	if err != nil {
		return rt, err
	}

	if signedVerify != signed {
		return tokenpb.RefreshToken{}, errors.New("invalid token")
	}

	rt, errDecode := DecodeRT(payload)

	if errDecode != nil {
		return tokenpb.RefreshToken{}, errDecode
	}

	if int64(rt.Exp) < time.Now().Unix() {
		return tokenpb.RefreshToken{}, errors.New("expired token")
	}

	return rt, nil
}
