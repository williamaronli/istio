//  Copyright 2019 Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package sdsingress

import (
	"testing"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/ingress"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/resource/environment"
	ingressutil "istio.io/istio/tests/integration/security/sds_ingress/util"
)

var (
	inst istio.Instance
)

func TestMain(m *testing.M) {
	// Integration test for the ingress SDS Gateway flow.
	framework.
		NewSuite("sds_ingress", m).
		RequireSingleCluster().
		SetupOnEnv(environment.Kube, istio.Setup(&inst, nil)).
		Run()
}

func TestSingleTlsGateway_SecretRotation(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {

			var (
				credName = "testsingletlsgateway-secretrotation"
				host     = "testsingletlsgateway-secretrotation.example.com"
			)
			// Add kubernetes secret to provision key/cert for ingress gateway.
			ingressutil.CreateIngressKubeSecret(t, ctx, []string{credName}, ingress.TLS, ingressutil.IngressCredentialA, false)
			defer ingressutil.DeleteIngressKubeSecret(t, ctx, []string{credName})

			ns := ingressutil.SetupTest(ctx)
			ingressutil.SetupConfig(t, ctx, ns, ingressutil.TestConfig{
				Mode:           "SIMPLE",
				CredentialName: credName,
				Host:           host,
			})

			ingA := ingress.NewOrFail(t, ctx, ingress.Config{Istio: inst})
			tlsContext := ingressutil.TLSContext{CaCert: ingressutil.CaCertA}
			err := ingressutil.SendRequest(ingA, host, credName, ingress.TLS, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
			if err != nil {
				t.Fatalf("unable to retrieve 200 from product page at host %s: %v", host, err)
			}

			// key/cert rotation
			ingressutil.RotateSecrets(t, ctx, []string{credName}, ingress.TLS, ingressutil.IngressCredentialB)
			// Client use old server CA cert to set up SSL connection would fail.
			err = ingressutil.SendRequest(ingA, host, credName, ingress.TLS, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 0, ErrorMessage: "certificate signed by unknown authority"}, t)
			if err != nil {
				t.Fatalf("unable to retrieve 404 from product page at host %s: %v", host, err)
			}

			// Client use new server CA cert to set up SSL connection.
			tlsContext = ingressutil.TLSContext{CaCert: ingressutil.CaCertB}
			ingB := ingress.NewOrFail(t, ctx, ingress.Config{Istio: inst})
			err = ingressutil.SendRequest(ingB, host, credName, ingress.TLS, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
			if err != nil {
				t.Fatalf("unable to retrieve 200 from product page at host %s: %v", host, err)
			}
		})
}

// TestSingleMTLSGateway_ServerKeyCertRotation tests a single mTLS ingress gateway with SDS enabled.
// Verifies behavior in these scenarios.
// (1) create two kubernetes secrets to provision server key/cert and client CA cert, and
// verify that mTLS connection could establish to deliver HTTPS request.
// (2) replace kubernetes secret to rotate server key/cert, and verify that mTLS connection could
// not establish. This is because client is still using old server CA cert to validate server cert,
// and the new server cert cannot pass validation at client side.
// (3) do another key/cert rotation to use the correct server key/cert this time, and verify that
// mTLS connection could establish to deliver HTTPS request.
func TestSingleMTLSGateway_ServerKeyCertRotation(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {

			var (
				credName   = []string{"testsinglemtlsgateway-serverkeycertrotation"}
				credCaName = []string{"testsinglemtlsgateway-serverkeycertrotation-cacert"}
				host       = "testsinglemtlsgateway-serverkeycertrotation.example.com"
			)

			ns := ingressutil.SetupTest(ctx)
			ingressutil.SetupConfig(t, ctx, ns, ingressutil.TestConfig{
				Mode:           "MUTUAL",
				CredentialName: credName[0],
				Host:           host,
			})

			// Add two kubernetes secrets to provision server key/cert and client CA cert for ingress gateway.
			ingressutil.CreateIngressKubeSecret(t, ctx, credCaName, ingress.Mtls, ingressutil.IngressCredentialCaCertA, true)
			ingressutil.CreateIngressKubeSecret(t, ctx, credName, ingress.Mtls,
				ingressutil.IngressCredentialServerKeyCertA, true)
			defer ingressutil.DeleteIngressKubeSecret(t, ctx, credName)
			defer ingressutil.DeleteIngressKubeSecret(t, ctx, credCaName)

			ingA := ingress.NewOrFail(t, ctx, ingress.Config{Istio: inst})
			tlsContext := ingressutil.TLSContext{
				CaCert:     ingressutil.CaCertA,
				PrivateKey: ingressutil.TLSClientKeyA,
				Cert:       ingressutil.TLSClientCertA,
			}
			err := ingressutil.SendRequest(ingA, host, credName[0], ingress.Mtls, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
			if err != nil {
				t.Fatalf("unable to retrieve code 200 from product page at host %s: %v", host, err)
			}

			// key/cert rotation using mis-matched server key/cert. The server cert cannot pass validation
			// at client side.
			ingressutil.RotateSecrets(t, ctx, credName, ingress.Mtls, ingressutil.IngressCredentialServerKeyCertB)
			// Client uses old server CA cert to set up SSL connection would fail.
			err = ingressutil.SendRequest(ingA, host, credName[0], ingress.Mtls, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 0, ErrorMessage: "certificate signed by unknown authority"}, t)
			if err != nil {
				t.Fatalf("unable to retrieve 0 from product page at host %s: %v", host, err)
			}

			// key/cert rotation using matched server key/cert. This time the server cert is able to pass
			// validation at client side.
			ingressutil.RotateSecrets(t, ctx, credName, ingress.Mtls, ingressutil.IngressCredentialServerKeyCertA)
			// Use old CA cert to set up SSL connection would succeed this time.
			err = ingressutil.SendRequest(ingA, host, credName[0], ingress.Mtls, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
			if err != nil {
				t.Fatalf("unable to retrieve code 200 from product page at host %s: %v", host, err)
			}
		})
}

// TestSingleMTLSGateway_CompoundSecretRotation tests a single mTLS ingress gateway with SDS enabled.
// Verifies behavior in these scenarios.
// (1) A valid kubernetes secret with key/cert and client CA cert is added, verifies that SSL connection
// termination is working properly. This secret is a compound secret.
// (2) After key/cert rotation, client needs to pick new CA cert to complete SSL connection. Old CA
// cert will cause the SSL connection fail.
func TestSingleMTLSGateway_CompoundSecretRotation(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			var (
				credName = []string{"testsinglemtlsgateway-compoundsecretrotation"}
				host     = "testsinglemtlsgateway-compoundsecretrotation.example.com"
			)

			// Add kubernetes secret to provision key/cert for ingress gateway.
			ingressutil.CreateIngressKubeSecret(t, ctx, credName, ingress.Mtls, ingressutil.IngressCredentialA, true)
			defer ingressutil.DeleteIngressKubeSecret(t, ctx, credName)

			ns := ingressutil.SetupTest(ctx)
			ingressutil.SetupConfig(t, ctx, ns, ingressutil.TestConfig{
				Mode:           "MUTUAL",
				CredentialName: credName[0],
				Host:           host,
			})
			// Wait for ingress gateway to fetch key/cert from Gateway agent via SDS.
			ing := ingress.NewOrFail(t, ctx, ingress.Config{Istio: inst})
			tlsContext := ingressutil.TLSContext{
				CaCert:     ingressutil.CaCertA,
				PrivateKey: ingressutil.TLSClientKeyA,
				Cert:       ingressutil.TLSClientCertA,
			}
			err := ingressutil.SendRequest(ing, host, credName[0], ingress.Mtls, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
			if err != nil {
				t.Fatalf("unable to retrieve 200 from product page at host %s: %v", host, err)
			}

			// key/cert rotation
			ingressutil.RotateSecrets(t, ctx, credName, ingress.Mtls, ingressutil.IngressCredentialB)
			// Use old server CA cert to set up SSL connection would fail.
			err = ingressutil.SendRequest(ing, host, credName[0], ingress.Mtls, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 0, ErrorMessage: "certificate signed by unknown authority"}, t)
			if err != nil {
				t.Fatalf("unable to retrieve 404 from product page at host %s: %v", host, err)
			}

			// Use new server CA cert to set up SSL connection.
			tlsContext = ingressutil.TLSContext{
				CaCert:     ingressutil.CaCertB,
				PrivateKey: ingressutil.TLSClientKeyB,
				Cert:       ingressutil.TLSClientCertB,
			}
			err = ingressutil.SendRequest(ing, host, credName[0], ingress.Mtls, tlsContext,
				ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
			if err != nil {
				t.Fatalf("unable to retrieve 200 from product page at host %s: %v", host, err)
			}
		})
}

func TestSingleMTLSGatewayWithCaCert_CompoundSecretRotation(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
			Run(func(ctx framework.TestContext) {
				var (
					credName = []string{"testsinglemtlsgatewaywithcacert-compoundsecretrotation"}
					host     = "testsinglemtlsgatewaywithcacert-compoundsecretrotation.example.com"
				)

				// Add kubernetes secret to provision key/cert for ingress gateway.
				ingressutil.CreateIngressKubeSecret(t, ctx, credName, ingress.Mtls, ingressutil.IngressCredentialA, true)
				defer ingressutil.DeleteIngressKubeSecret(t, ctx, credName)

				ns := ingressutil.SetupTest(ctx)
				ingressutil.SetupConfig(t, ctx, ns, ingressutil.TestConfig{
					Mode:           "MUTUAL",
					CredentialName: credName[0],
					Host:           host,
				})
				// Wait for ingress gateway to fetch key/cert from Gateway agent via SDS.
				ing := ingress.NewOrFail(t, ctx, ingress.Config{Istio: inst})
				tlsContext := ingressutil.TLSContext{
					CaCert:     ingressutil.CaCertA,
					PrivateKey: ingressutil.TLSClientKeyA,
					Cert:       ingressutil.TLSClientCertA,
				}
				err := ingressutil.SendRequest(ing, host, credName[0], ingress.Mtls, tlsContext,
					ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
				if err != nil {
					t.Fatalf("unable to retrieve 200 from product page at host %s: %v", host, err)
				}

				// key/cert rotation
				ingressutil.RotateSecrets(t, ctx, credName, ingress.Mtls, ingressutil.IngressCredentialB)
				// Use old server CA cert to set up SSL connection would fail.
				err = ingressutil.SendRequest(ing, host, credName[0], ingress.Mtls, tlsContext,
					ingressutil.ExpectedResponse{ResponseCode: 0, ErrorMessage: "certificate signed by unknown authority"}, t)
				if err != nil {
					t.Fatalf("unable to retrieve 404 from product page at host %s: %v", host, err)
				}

				// Use new server CA cert to set up SSL connection.
				tlsContext = ingressutil.TLSContext{
					CaCert:     ingressutil.CaCertB,
					PrivateKey: ingressutil.TLSClientKeyB,
					Cert:       ingressutil.TLSClientCertB,
				}
				err = ingressutil.SendRequest(ing, host, credName[0], ingress.Mtls, tlsContext,
					ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
				if err != nil {
					t.Fatalf("unable to retrieve 200 from product page at host %s: %v", host, err)
				}
			})
}

// TestTlsGateways deploys multiple TLS gateways with SDS enabled, and creates kubernetes that store
// private key and server certificate for each TLS gateway. Verifies that all gateways are able to terminate
// SSL connections successfully.
func TestTlsGateways(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			ingressutil.RunTestMultiTLSGateways(ctx, inst)
		})
}

// TestMtlsGateways deploys multiple mTLS gateways with SDS enabled, and creates kubernetes that store
// private key, server certificate and CA certificate for each mTLS gateway. Verifies that all gateways are able to terminate
// mTLS connections successfully.
func TestMtlsGateways(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			ingressutil.RunTestMultiMtlsGateways(ctx, inst)
		})
}

// TestMultiTlsGateway_InvalidSecret tests a single TLS ingress gateway with SDS enabled. Creates kubernetes secret
// with invalid key/cert and verify the behavior.
func TestMultiTlsGateway_InvalidSecret(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {

			ns := ingressutil.SetupTest(ctx)

			testCase := []struct {
				name                     string
				secretName               string
				ingressGatewayCredential ingressutil.IngressCredential
				ingressConfig            ingress.Config
				hostName                 string
				expectedResponse         ingressutil.ExpectedResponse
				callType                 ingress.CallType
				tlsContext               ingressutil.TLSContext
			}{
				{
					name:       "tls ingress gateway invalid private key",
					secretName: "testmultitlsgateway-invalidsecret-1",
					ingressGatewayCredential: ingressutil.IngressCredential{
						PrivateKey: "invalid",
						ServerCert: ingressutil.TLSServerCertA,
					},
					ingressConfig: ingress.Config{
						Istio: inst,
					},
					hostName: "testmultitlsgateway-invalidsecret1.example.com",
					expectedResponse: ingressutil.ExpectedResponse{
						ResponseCode: 0,
						// TODO(JimmyCYJ): Temporarily skip verification of error message to deflake test.
						//  Need a more accurate way to verify the request failures.
						// https://github.com/istio/istio/issues/16998
						ErrorMessage: "",
					},
					callType: ingress.TLS,
					tlsContext: ingressutil.TLSContext{
						CaCert: ingressutil.CaCertA,
					},
				},
				{
					name:       "tls ingress gateway invalid server cert",
					secretName: "testmultitlsgateway-invalidsecret-2",
					ingressGatewayCredential: ingressutil.IngressCredential{
						PrivateKey: ingressutil.TLSServerKeyA,
						ServerCert: "invalid",
					},
					ingressConfig: ingress.Config{
						Istio: inst,
					},
					hostName: "testmultitlsgateway-invalidsecret2.example.com",
					expectedResponse: ingressutil.ExpectedResponse{
						ResponseCode: 0,
						ErrorMessage: "",
					},
					callType: ingress.TLS,
					tlsContext: ingressutil.TLSContext{
						CaCert: ingressutil.CaCertA,
					},
				},
				{
					name:       "tls ingress gateway mis-matched key and cert",
					secretName: "testmultitlsgateway-invalidsecret-3",
					ingressGatewayCredential: ingressutil.IngressCredential{
						PrivateKey: ingressutil.TLSServerKeyA,
						ServerCert: ingressutil.TLSServerCertB,
					},
					ingressConfig: ingress.Config{
						Istio: inst,
					},
					hostName: "testmultitlsgateway-invalidsecret3.example.com",
					expectedResponse: ingressutil.ExpectedResponse{
						ResponseCode: 0,
						ErrorMessage: "",
					},
					callType: ingress.TLS,
					tlsContext: ingressutil.TLSContext{
						CaCert: ingressutil.CaCertA,
					},
				},
				{
					name:       "tls ingress gateway no private key",
					secretName: "testmultitlsgateway-invalidsecret-4",
					ingressGatewayCredential: ingressutil.IngressCredential{
						ServerCert: ingressutil.TLSServerCertA,
					},
					ingressConfig: ingress.Config{
						Istio: inst,
					},
					hostName: "testmultitlsgateway-invalidsecret4.example.com",
					expectedResponse: ingressutil.ExpectedResponse{
						ResponseCode: 0,
						ErrorMessage: "",
					},
					callType: ingress.TLS,
					tlsContext: ingressutil.TLSContext{
						CaCert: ingressutil.CaCertA,
					},
				},
				{
					name:       "tls ingress gateway no server cert",
					secretName: "testmultitlsgateway-invalidsecret-5",
					ingressGatewayCredential: ingressutil.IngressCredential{
						PrivateKey: ingressutil.TLSServerKeyA,
					},
					ingressConfig: ingress.Config{
						Istio: inst,
					},
					hostName: "testmultitlsgateway-invalidsecret5.example.com",
					expectedResponse: ingressutil.ExpectedResponse{
						ResponseCode: 0,
						ErrorMessage: "",
					},
					callType: ingress.TLS,
					tlsContext: ingressutil.TLSContext{
						CaCert: ingressutil.CaCertA,
					},
				},
			}

			for _, c := range testCase {
				ctx.NewSubTest(c.name).Run(func(t framework.TestContext) {
					ingressutil.CreateIngressKubeSecret(ctx, ctx, []string{c.secretName}, ingress.TLS,
						c.ingressGatewayCredential,false)
					defer ingressutil.DeleteIngressKubeSecret(ctx, ctx, []string{c.secretName})
					ing := ingress.NewOrFail(ctx, ctx, c.ingressConfig)

					ingressutil.SetupConfig(t, ctx, ns, ingressutil.TestConfig{
						Mode:           "SIMPLE",
						CredentialName: c.secretName,
						Host:           c.hostName,
					})
					err := ingressutil.SendRequest(ing, c.hostName, c.secretName, c.callType, c.tlsContext, c.expectedResponse, t)
					if err != nil {
						ctx.Fatalf("unable to retrieve %d from product page at host %s: %v", c.expectedResponse.ResponseCode, c.hostName, err)
					}
				})
			}
		})
}

// TestMultiMtlsGateway_InvalidSecret tests a single mTLS ingress gateway with SDS enabled. Creates kubernetes secret
// with invalid key/cert and verify the behavior.
func TestMultiMtlsGateway_InvalidSecret(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			ns := ingressutil.SetupTest(ctx)

			testCase := []struct {
				name                     string
				secretName               string
				ingressGatewayCredential ingressutil.IngressCredential
				ingressConfig            ingress.Config
				hostName                 string
				expectedResponse         ingressutil.ExpectedResponse
				callType                 ingress.CallType
				tlsContext               ingressutil.TLSContext
			}{
				{
					name:       "mtls ingress gateway invalid CA cert",
					secretName: "testmultimtlsgateway-invalidsecret-1",
					ingressGatewayCredential: ingressutil.IngressCredential{
						PrivateKey: ingressutil.TLSServerKeyA,
						ServerCert: ingressutil.TLSServerCertA,
						CaCert:     "invalid",
					},
					ingressConfig: ingress.Config{
						Istio: inst,
					},
					hostName: "testmultimtlsgateway-invalidsecret1.example.com",
					expectedResponse: ingressutil.ExpectedResponse{
						ResponseCode: 0,
						// TODO(JimmyCYJ): Temporarily skip verification of error message to deflake test.
						//  Need a more accurate way to verify the request failures.
						// https://github.com/istio/istio/issues/16998
						ErrorMessage: "",
					},
					callType: ingress.Mtls,
					tlsContext: ingressutil.TLSContext{
						CaCert:     ingressutil.CaCertA,
						PrivateKey: ingressutil.TLSClientKeyA,
						Cert:       ingressutil.TLSClientCertA,
					},
				},
				{
					name:       "mtls ingress gateway no CA cert",
					secretName: "testmultimtlsgateway-invalidsecret-2",
					ingressGatewayCredential: ingressutil.IngressCredential{
						PrivateKey: ingressutil.TLSServerKeyA,
						ServerCert: ingressutil.TLSServerCertA,
					},
					ingressConfig: ingress.Config{
						Istio: inst,
					},
					hostName: "testmultimtlsgateway-invalidsecret2.example.com",
					expectedResponse: ingressutil.ExpectedResponse{
						ResponseCode: 0,
						ErrorMessage: "",
					},
					callType: ingress.Mtls,
					tlsContext: ingressutil.TLSContext{
						CaCert:     ingressutil.CaCertA,
						PrivateKey: ingressutil.TLSClientKeyA,
						Cert:       ingressutil.TLSClientCertA,
					},
				},
				{
					name:       "mtls ingress gateway mismatched CA cert",
					secretName: "testmultimtlsgateway-invalidsecret-3",
					ingressGatewayCredential: ingressutil.IngressCredential{
						PrivateKey: ingressutil.TLSServerKeyA,
						ServerCert: ingressutil.TLSServerCertA,
						CaCert:     ingressutil.CaCertB,
					},
					ingressConfig: ingress.Config{
						Istio: inst,
					},
					hostName: "testmultimtlsgateway-invalidsecret3.example.com",
					expectedResponse: ingressutil.ExpectedResponse{
						ResponseCode: 0,
						ErrorMessage: "",
					},
					callType: ingress.Mtls,
					tlsContext: ingressutil.TLSContext{
						CaCert:     ingressutil.CaCertA,
						PrivateKey: ingressutil.TLSClientKeyA,
						Cert:       ingressutil.TLSClientCertA,
					},
				},
			}

			for _, c := range testCase {
				ctx.NewSubTest(c.name).Run(func(ctx framework.TestContext) {
					ingressutil.CreateIngressKubeSecret(t, ctx, []string{c.secretName}, ingress.Mtls,
						c.ingressGatewayCredential, true)
					defer ingressutil.DeleteIngressKubeSecret(t, ctx, []string{c.secretName})

					ingressutil.SetupConfig(t, ctx, ns, ingressutil.TestConfig{
						Mode:           "MUTUAL",
						CredentialName: c.secretName,
						Host:           c.hostName,
					})
					ing := ingress.NewOrFail(t, ctx, c.ingressConfig)
					err := ingressutil.SendRequest(ing, c.hostName, c.secretName, c.callType, c.tlsContext, c.expectedResponse, t)
					if err != nil {
						ctx.Fatalf("unable to retrieve %d from product page at host %s: %v", c.expectedResponse.ResponseCode, c.hostName, err)
					}
				})
			}
		})
}
