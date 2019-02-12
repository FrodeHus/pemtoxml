package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var _privateKeyFile string
var _publicKeyFile string

//RsaPublicKey represents a XML structure for a RSA public key
type RsaPublicKey struct {
	XMLName  xml.Name `xml:"RSAKeyValue"`
	Modulus  string   `xml:"Modulus"`
	Exponent string   `xml:"Exponent"`
}

//RsaPrivateKey represents a XML structure for a RSA private key
type RsaPrivateKey struct {
	XMLName  xml.Name `xml:"RSAKeyValue"`
	Modulus  string   `xml:"Modulus"`
	Exponent string   `xml:"Exponent"`
	D        string   `xml:"D"`
	P        string   `xml:"P"`
	Q        string   `xml:"Q"`
	DP       string   `xml:"DP"`
	DQ       string   `xml:"DQ"`
	InverseQ string   `xml:"InverseQ"`
}

func init() {
	flag.StringVar(&_privateKeyFile, "privateKey", "./private.pem", "Path to private key")
	flag.StringVar(&_publicKeyFile, "publicKey", "", "Path to public key")
}

func main() {
	if _privateKeyFile != "" {
		fmt.Println("Generating XML from private key...")
		privKey := &RsaPrivateKey{}
		xml, err := privKey.GenerateXMLFrom(_privateKeyFile)
		if err != nil {
			os.Exit(1)
		}

		ioutil.WriteFile("private.xml", xml, os.FileMode(0755))
	}
	if _publicKeyFile != "" {
		fmt.Println("Generating XML from public key...")
		publicKey := &RsaPublicKey{}
		xml, err := publicKey.GenerateXMLFrom(_publicKeyFile)
		if err != nil {
			os.Exit(1)
		}

		ioutil.WriteFile("public.xml", xml, os.FileMode(0755))
	}
}

//GenerateXMLFrom returns XML for the specified public key PEM file
func (key *RsaPublicKey) GenerateXMLFrom(publicKeyFile string) ([]byte, error) {
	keyfile, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		fmt.Printf("Failed to read public key: %s\n", err)
		return nil, err
	}

	publicPem, _ := pem.Decode(keyfile)
	parsedKey, err := x509.ParsePKCS1PublicKey(publicPem.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse public key: %s\n", err)
		return nil, err
	}

	e, _ := IntToBytes(parsedKey.E)
	key.Modulus = base64.StdEncoding.EncodeToString(parsedKey.N.Bytes())
	key.Exponent = base64.StdEncoding.EncodeToString(e)

	return xml.MarshalIndent(key, "", "	")
}

// GenerateXMLFrom returns XML for the specified private key PEM file
func (key *RsaPrivateKey) GenerateXMLFrom(privateKeyFile string) ([]byte, error) {
	keyfile, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		fmt.Printf("Failed to read private key: %s\n", err)
		return nil, err
	}

	privPem, _ := pem.Decode(keyfile)
	parsedKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse private key: %s\n", err)
		return nil, err
	}

	e, _ := IntToBytes(parsedKey.E)

	key.Modulus = base64.StdEncoding.EncodeToString(parsedKey.N.Bytes())
	key.Exponent = base64.RawURLEncoding.EncodeToString(e)
	key.D = base64.StdEncoding.EncodeToString(parsedKey.D.Bytes())
	key.P = base64.StdEncoding.EncodeToString(parsedKey.Primes[0].Bytes())
	key.Q = base64.StdEncoding.EncodeToString(parsedKey.Primes[1].Bytes())
	key.DP = base64.StdEncoding.EncodeToString(parsedKey.Precomputed.Dp.Bytes())
	key.DQ = base64.StdEncoding.EncodeToString(parsedKey.Precomputed.Dq.Bytes())
	key.InverseQ = base64.StdEncoding.EncodeToString(parsedKey.Precomputed.Qinv.Bytes())
	return xml.MarshalIndent(key, "", "	")
}

//IntToBytes converts an int value to a byte array
func IntToBytes(value int) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, int32(value))
	if err != nil {
		return nil, err
	}
	bytes := buf.Bytes()
	return bytes[:3], nil
}
