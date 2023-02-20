package tokutil

import (
	"crypto/hmac"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"
	jsoniter "github.com/json-iterator/go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"log"
	tokenpb "github.com/ijmae/tokutil/protobuf/tokenpb"
	"strings"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func encode(decoded protoreflect.ProtoMessage) (string, error) {
	out, err := proto.Marshal(decoded)

	if err != nil {
		return "", err
	}

	return b64.RawURLEncoding.EncodeToString([]byte(out)), nil
}

func EncodeAT(decoded *tokenpb.AccessToken) string {
	out, err := encode(decoded)

	if err != nil {
		log.Fatalln("Failed to encode access token:", err)
	}

	return out
}

func EncodeRT(decoded *tokenpb.RefreshToken) string {
	out, err := encode(decoded)

	if err != nil {
		log.Fatalln("Failed to encode refresh token:", err)
	}

	return out
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
		log.Fatalln("Failed to decode access token - Decode base64:", err)
		return at, err
	}

	return at, nil
}

func DecodeRT(encodedBase64URL string) (tokenpb.RefreshToken, error) {
	var rt tokenpb.RefreshToken

	if err := decode(encodedBase64URL, &rt); err != nil {
		log.Fatalln("Failed to decode refresh token - Decode base64:", err)
		return rt, err
	}

	return rt, nil
}

func DecodeATToJSON(encodedBase64URL string) (string, error) {
	var at tokenpb.AccessToken

	if err := decode(encodedBase64URL, &at); err != nil {
		log.Fatalln("Failed to decode access token - Decode base64:", err)
		return "", err
	}

	json, errToJSON := json.Marshal(at)

	if errToJSON != nil {
		log.Fatalln("Failed to decode access token - To JSON:", errToJSON)
		return "", errToJSON
	}

	return string(json), nil
}

func DecodeRToJSON(encodedBase64URL string) (string, error) {
	var rt tokenpb.RefreshToken

	if err := decode(encodedBase64URL, &rt); err != nil {
		log.Fatalln("Failed to decode refresh token - Decode base64:", err)
		return "", err
	}

	json, errToJSON := json.Marshal(rt)

	if errToJSON != nil {
		log.Fatalln("Failed to decode refresh token - To JSON:", errToJSON)
		return "", errToJSON
	}

	return string(json), nil
}

func doHMAC(input, secret, outType string) string {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(input))

	// Convert to []byte
	b := h.Sum(nil)

	if outType == "base64" {
		return b64.RawStdEncoding.EncodeToString(b)
	}

	if outType == "base64URL" {
		return b64.RawURLEncoding.EncodeToString(b)
	}

	return hex.EncodeToString(b)

}

func SignAT(payload tokenpb.AccessToken, secret string) string {

	encodedAT := EncodeAT(&payload)

	signedAT := doHMAC(encodedAT, secret, "base64URL")

	var s strings.Builder

	s.WriteString(encodedAT)
	s.WriteString(".")
	s.WriteString(signedAT)

	return s.String()
}

func SignRT(payload tokenpb.RefreshToken, secret string) string {

	encodedAT := EncodeRT(&payload)

	signedAT := doHMAC(encodedAT, secret, "base64URL")

	var s strings.Builder

	s.WriteString(encodedAT)
	s.WriteString(".")
	s.WriteString(signedAT)

	return s.String()
}

func VerifyAT(token, secret string) (tokenpb.AccessToken, error) {

	tokenArr := strings.Split(token, ".")

	payload := tokenArr[0]

	signed := tokenArr[1]

	signedVerify := doHMAC(payload, secret, "base64URL")

	if signedVerify != signed {
		return tokenpb.AccessToken{}, errors.New("invalid token")
	}

	at, errDecode := DecodeAT(payload)

	if errDecode != nil {
		log.Fatalln("Failed to decode access token - Decode proto:", errDecode)
		return tokenpb.AccessToken{}, errDecode
	}

	return at, nil
}

func VerifyRT(token, secret string) (tokenpb.RefreshToken, error) {

	tokenArr := strings.Split(token, ".")

	payload := tokenArr[0]

	signed := tokenArr[1]

	signedVerify := doHMAC(payload, secret, "base64URL")

	if signedVerify != signed {
		return tokenpb.RefreshToken{}, errors.New("invalid token")
	}

	rt, errDecode := DecodeRT(payload)

	if errDecode != nil {
		log.Fatalln("Failed to decode refresh token - Decode proto:", errDecode)
		return tokenpb.RefreshToken{}, errDecode
	}

	return rt, nil
}
