package main

import (
	"bytes"
	"crypto/rsa"
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
	flag.StringVar(&_privateKeyFile, "privateKey", "private.pem", "Path to private key")
	flag.Parse()
}

func main() {
	if _privateKeyFile != "" {
		keyfile, err := ioutil.ReadFile(_privateKeyFile)
		if err != nil {
			fmt.Printf("Failed to read private key: %s\n", err)
			os.Exit(1)
		}

		publicPem, _ := pem.Decode(keyfile)
		parsedKey, err := x509.ParsePKCS1PrivateKey(publicPem.Bytes)
		if err != nil {
			fmt.Printf("Failed to parse private key: %s\n", err)
			os.Exit(1)
		}

		privKey := &RsaPrivateKey{}
		privateXML, err := privKey.GenerateXMLFrom(parsedKey)
		if err != nil {
			os.Exit(1)
		}

		ioutil.WriteFile("private.pem.xml", privateXML, os.FileMode(0755))

		publicKey := &RsaPublicKey{}
		publicXML, err := publicKey.GenerateXMLFrom(parsedKey)
		if err != nil {
			os.Exit(1)
		}

		ioutil.WriteFile("public.pem.xml", publicXML, os.FileMode(0755))
	}
}

//GenerateXMLFrom returns XML for the specified public key PEM file
func (key *RsaPublicKey) GenerateXMLFrom(privateKey *rsa.PrivateKey) ([]byte, error) {
	fmt.Println("Generating XML for public key...")

	publicKey := privateKey.PublicKey

	e, _ := IntToBytes(publicKey.E)
	key.Modulus = base64.StdEncoding.EncodeToString(publicKey.N.Bytes())
	key.Exponent = base64.StdEncoding.EncodeToString(e)

	return xml.MarshalIndent(key, "", "	")
}

// GenerateXMLFrom returns XML for the specified private key PEM file
func (key *RsaPrivateKey) GenerateXMLFrom(privateKey *rsa.PrivateKey) ([]byte, error) {
	fmt.Println("Generating XML for private key...")

	e, _ := IntToBytes(privateKey.E)

	key.Modulus = base64.StdEncoding.EncodeToString(privateKey.N.Bytes())
	key.Exponent = base64.RawURLEncoding.EncodeToString(e)
	key.D = base64.StdEncoding.EncodeToString(privateKey.D.Bytes())
	key.P = base64.StdEncoding.EncodeToString(privateKey.Primes[0].Bytes())
	key.Q = base64.StdEncoding.EncodeToString(privateKey.Primes[1].Bytes())
	key.DP = base64.StdEncoding.EncodeToString(privateKey.Precomputed.Dp.Bytes())
	key.DQ = base64.StdEncoding.EncodeToString(privateKey.Precomputed.Dq.Bytes())
	key.InverseQ = base64.StdEncoding.EncodeToString(privateKey.Precomputed.Qinv.Bytes())
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
