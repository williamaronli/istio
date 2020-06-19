package sdsservice

import (
	"fmt"
	"net"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"istio.io/istio/pkg/istio-agent"
	"istio.io/istio/pkg/test/env"
	sdsTest "istio.io/istio/security/pkg/nodeagent/test"

	"golang.org/x/net/context"
)

const (
	credentialTokenHeaderKey = "authorization"
	fakeToken1        = "faketoken1"
	SecretTypeV3 = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
	testResourceName  = "default"
)

type notifyMsg struct {
	Err     error
	Message string
}

type Setup struct {
		t * testing.T
		socket string
}

func TestSDSAgentWithCacheAndConnectionCleaned(t *testing.T) {
	setup := sdsTest.SetupTest(t,env.SDSStreamTest)
	sa := *istioagent.NewSDSAgent("istiod.istio-system:15012", false, "custom", "", "", "kubernetes")

	_, err := sa.Start(true, "test")
	if err != nil {
		t.Fatalf("Unexpected error starting SDSAgent %v", err)
	}
	notifyChan := make(chan notifyMsg)

	proxyID := "sidecar~127.0.0.1~SecretsPushStreamOne~local"
	connOne, streamOne := createSDSStream(t, sa.SDSAddress, fakeToken1)
	defer connOne.Close()
	go testSDSStreamTwo(streamOne, proxyID, notifyChan)
	waitForNotificationToProceed(t, notifyChan, "notify push secret")
	waitForNotificationToProceed(t, notifyChan, "close stream")
	//sa.Start()
}

func testSDSStreamTwo(stream sds.SecretDiscoveryService_StreamSecretsClient, proxyID string,
		notifyChan chan notifyMsg) {
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
	if err := stream.Send(req); err != nil {
		notifyChan <- notifyMsg{Err: err, Message: fmt.Sprintf(
			"stream: stream.Send failed: %v", err)}
	}
	notifyChan <- notifyMsg{Err: nil, Message: "notify push secret"}
	_, err := stream.Recv()
	if err != nil {
		notifyChan <- notifyMsg{Err: err, Message: fmt.Sprintf(
			"stream: stream.Recv failed: %v", err)}
	}

	notifyChan <- notifyMsg{Err: nil, Message: "close stream"}
}

func createSDSStream(t *testing.T, socket, token string) (*grpc.ClientConn, sds.SecretDiscoveryService_StreamSecretsClient) {
	// Try to call the server
	conn, err := setupConnection(socket)
	if err != nil {
		t.Errorf("failed to setup connection to socket %q", socket)
	}
	sdsClient := sds.NewSecretDiscoveryServiceClient(conn)
	header := metadata.Pairs(credentialTokenHeaderKey, token)
	ctx := metadata.NewOutgoingContext(context.Background(), header)
	stream, err := sdsClient.StreamSecrets(ctx)
	if err != nil {
		t.Errorf("StreamSecrets failed: %v", err)
	}
	return conn, stream
}

func setupConnection(socket string) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	opts = append(opts, grpc.WithInsecure(), grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}))

	conn, err := grpc.Dial(socket, opts...)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func waitForNotificationToProceed(t *testing.T, notifyChan chan notifyMsg, proceedNotice string) {
	for {
		if notify := <-notifyChan; notify.Err != nil {
			t.Logf("%v",notify)
			t.Logf("%v",notify.Err)
			t.Logf("%s",notify.Message)
			t.Fatalf("get error from stream: %v", notify.Message)
		} else {
			if notify.Message != proceedNotice {
				t.Fatalf("push signal does not match, expected %s but got %s", proceedNotice,
					notify.Message)
			}
			return
		}
	}
}

//func TestStreamSecretsPush(t *testing.T) {
//	setup := StartTest(t)
//	defer setup.server.Stop()
//
//	var expectedTotalPush int64
//
//	connOne, streamOne := createSDSStream(t, setup.socket, fakeToken1)
//	defer connOne.Close()
//	proxyID := "sidecar~127.0.0.1~SecretsPushStreamOne~local"
//	notifyChanOne := make(chan notifyMsg)
//	go testSDSStreamOne(streamOne, proxyID, notifyChanOne)
//	expectedTotalPush += 2
//
//	connTwo, streamTwo := createSDSStream(t, setup.socket, fakeToken2)
//	defer connTwo.Close()
//	proxyIDTwo := "sidecar~127.0.0.1~SecretsPushStreamTwo~local"
//	notifyChanTwo := make(chan notifyMsg)
//	go testSDSStreamTwo(streamTwo, proxyIDTwo, notifyChanTwo)
//	expectedTotalPush++
//
//	// verify that the first SDS request sent by two streams do not hit cache.
//	waitForSecretCacheCheck(t, setup.secretStore, false, 2)
//	waitForNotificationToProceed(t, notifyChanOne, "notify push secret 1")
//	// verify that the second SDS request hits cache.
//	waitForSecretCacheCheck(t, setup.secretStore, true, 1)
//
//	// simulate logic in constructConnectionID() function.
//	conID := getClientConID(proxyID)
//	// Test push new secret to proxy. This SecretItem is for StreamOne.
//	if err := NotifyProxy(cache.ConnKey{ConnectionID: conID, ResourceName: testResourceName},
//		setup.generatePushSecret(conID, fakeToken1)); err != nil {
//		t.Fatalf("failed to send push notification to proxy %q: %v", conID, err)
//	}
//	notifyChanOne <- notifyMsg{Err: nil, Message: "receive secret"}
//
//	// Verify that pushed secret is stored in cache.
//	key := cache.ConnKey{
//		ConnectionID: conID,
//		ResourceName: testResourceName,
//	}
//	if _, found := setup.secretStore.secrets.Load(key); !found {
//		t.Fatalf("Failed to find cached secret")
//	}
//
//	waitForNotificationToProceed(t, notifyChanOne, "notify push secret 2")
//	// verify that the third SDS request hits cache.
//	waitForSecretCacheCheck(t, setup.secretStore, true, 2)
//
//	// Test push nil secret(indicates close the streaming connection) to proxy.
//	if err := NotifyProxy(cache.ConnKey{ConnectionID: conID, ResourceName: testResourceName}, nil); err != nil {
//		t.Fatalf("failed to send push notification to proxy %q", conID)
//	}
//	notifyChanOne <- notifyMsg{Err: nil, Message: "receive nil secret"}
//
//	waitForNotificationToProceed(t, notifyChanOne, "close stream")
//	waitForNotificationToProceed(t, notifyChanTwo, "close stream")
//
//	if _, found := setup.secretStore.secrets.Load(key); found {
//		t.Fatalf("Found cached secret after stream close, expected the secret to not exist")
//	}
//
//	recycleConnection(getClientConID(proxyID), testResourceName)
//	recycleConnection(getClientConID(proxyIDTwo), testResourceName)
//	clearStaledClients()
//	// Add RLock to avoid racetest fail.
//	sdsClientsMutex.RLock()
//	if len(sdsClients) != 0 {
//		t.Fatalf("sdsClients, got %d, expected 0", len(sdsClients))
//	}
//	sdsClientsMutex.RUnlock()
//
//	setup.verifyTotalPushes(expectedTotalPush)
//}