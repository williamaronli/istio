package sds

import (
	"fmt"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
)

func TestSDSAgentWithCacheAndConnectionCleaned(t *testing.T){
	fmt.Printf("==============")
	t.Log("TestSDSAgentWithCacheAndConnectionCleaned111111")
	//t.Skip("TestSDSAgentWithCacheAndConnectionCleaned111111")
	//t.Errorf("TestSDSAgentWithCacheAndConnectionCleaned111111")
	setup := StartTest(t)
	defer setup.server.Stop()

	conn, stream := createSDSStream(t, setup.socket, fakeToken1)
	//defer conn.Close()
	proxyID := "sidecar~127.0.0.1~SecretsPushStreamOne~local"
	notifyChan := make(chan notifyMsg)

	go testSDSStreamCache(stream, proxyID, notifyChan, conn)
	// verify that the first SDS request sent by two streams do not hit cache.
	waitForSecretCacheCheck(t, setup.secretStore, false, 1)

	setup.secretStore.secrets.Range(func(key, value interface{}) bool {
		t.Logf("secretStore: secrets %s", key)
		return true
	})
	//conn.Close()
	stream.CloseSend()
	waitForNotificationToProceed(t, notifyChan, "notify push secret 1")
	t.Log("22222222222")
	setup.secretStore.secrets.Range(func(key, value interface{}) bool {
		t.Logf("secretStore: secrets %s", key)
		return true
	})

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