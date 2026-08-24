package a10_test

import (
	"context"
	"log"
	"os"

	"github.com/vpgc/a10-certctl/pkg/a10"
)

func ExampleClient_SyncCertificate() {
	certificatePEM, err := os.ReadFile("fullchain.pem")
	if err != nil {
		log.Print(err)
		return
	}
	privateKeyPEM, err := os.ReadFile("privkey.pem")
	if err != nil {
		log.Print(err)
		return
	}
	bundle, err := a10.ParseCertificateBundle(a10.CertificateBundleInput{
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
	})
	if err != nil {
		log.Print(err)
		return
	}
	template, err := a10.ParseClientSSLTemplateName("www-client-tls")
	if err != nil {
		log.Print(err)
		return
	}
	client, err := a10.New(a10.Config{
		Address:  "a10.example.com",
		Username: os.Getenv("A10_USERNAME"),
		Password: os.Getenv("A10_PASSWORD"),
	})
	if err != nil {
		log.Print(err)
		return
	}
	_, err = client.SyncCertificate(
		context.Background(),
		a10.ForClientSSLTemplate(template),
		bundle,
		a10.SyncOptions{},
	)
	if err != nil {
		log.Print(err)
	}
}
