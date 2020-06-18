package sds

import (
	"fmt"
	"testing"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

const (
	// SecretType is used for secret discovery service to construct response.
	SecretTypeV2 = "type.googleapis.com/envoy.api.v2.auth.Secret"
	SecretTypeV3 = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

	// credentialTokenHeaderKey is the header key in gPRC header which is used to
	// pass credential token from envoy's SDS request to SDS service.
	credentialTokenHeaderKey = "authorization"

	// K8sSAJwtTokenHeaderKey is the request header key for k8s jwt token.
	// Binary header name must has suffix "-bin", according to https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md.
	// Same value defined in pilot pkg(k8sSAJwtTokenHeaderKey)
	k8sSAJwtTokenHeaderKey = "istio_sds_credentials_header-bin"
)

func TestSDSAgentWithCacheAndConnectionCleaned(t *testing.T){
	setup := StartTest(t)
	defer setup.server.Stop()

	conn, stream := createSDSStream(t, setup.socket, fakeToken1)
	defer conn.Close()
	proxyID := "sidecar~127.0.0.1~SecretsPushStreamOne~local"
	notifyChan := make(chan notifyMsg)

	go testSDSStreamOne(stream, proxyID, notifyChan)
	// verify that the first SDS request sent by two streams do not hit cache.
	waitForSecretCacheCheck(t, setup.secretStore, false, 2)
	waitForNotificationToProceed(t, notifyChan, "notify push secret 1")

}

func testSDSStreamCache(stream sds.SecretDiscoveryService_StreamSecretsClient, proxyID string,
		notifyChan chan notifyMsg, conn *grpc.ClientConn) {
		req := &discovery.DiscoveryRequest{
			TypeUrl:       SecretTypeV3,
		ResourceNames: []string{testResourceName},
		Node: &core.Node{
			Id: proxyID,
		},
		// Set a non-empty version info so that StreamSecrets() starts a cache check, and cache miss
		// metric is updated accordingly.
		VersionInfo: "initial_version",
	}
	// Send first request and verify response
	if err := stream.Send(req); err != nil {
		notifyChan <- notifyMsg{Err: err, Message: fmt.Sprintf("stream one: stream.Send failed: %v", err)}
	}

	resp, err := stream.Recv()
	if err != nil {
		notifyChan <- notifyMsg{Err: err, Message: fmt.Sprintf("stream one: stream.Recv failed: %v", err)}
	}
	if err := verifySDSSResponse(resp, fakePrivateKey, fakeCertificateChain); err != nil {
		notifyChan <- notifyMsg{Err: err, Message: fmt.Sprintf(
			"stream one: first SDS response verification failed: %v", err)}
	}
	notifyChan <- notifyMsg{Err: nil, Message: "notify push secret 1"}
}