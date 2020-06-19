package sds

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"istio.io/istio/security/pkg/nodeagent/cache"
	"istio.io/istio/security/pkg/nodeagent/model"
	"istio.io/istio/security/pkg/nodeagent/util"
	"k8s.io/apimachinery/pkg/util/uuid"
)

const (
	ValidProxyID = "sidecar~127.0.0.1~SecretsPushStreamOne~local"
	InValidProxyID = "invalid~sidecar~127.0.0.1~SecretsPushStreamOne~local"
)

func TestSDSAgentStreamWithCacheAndConnectionCleaned(t *testing.T){
	fmt.Printf("==============")
	t.Log("TestSDSAgentWithCacheAndConnectionCleaned111111")
	//t.Skip("TestSDSAgentWithCacheAndConnectionCleaned111111")
	//t.Errorf("TestSDSAgentWithCacheAndConnectionCleaned111111")
	setup := StartStreamTest(t)
	defer setup.server.Stop()

	conn, stream := createSDSStream(t, setup.socket, fakeToken1)
	//defer conn.Close()
	notifyChan := make(chan notifyMsg)


	t.Log("00000000")
	t.Log("sssssss")

	go testSDSIngressStreamCache(stream, ValidProxyID, notifyChan, conn)
	// verify that the first SDS request sent by two streams do not hit cache.
	waitForStreamSecretCacheCheck(t, setup.secretStore, false, 1)

	t.Log("111111111")
	t.Logf("sdsClient %v ",len(sdsClients))
	for key, val := range sdsClients {
		t.Logf("key is : %v, value is : %v", key,val)
	}
	//conID := getClientConID(ValidProxyID)
	t.Log(getClientConID(ValidProxyID))
	t.Log(getClientConID(InValidProxyID))
	//if err := NotifyProxy(cache.ConnKey{ConnectionID: conID, ResourceName: testResourceName},
	//	setup.generatePushSecret(conID, fakeToken1)); err != nil {
	//	t.Fatalf("failed to send push notification to proxy %q: %v", conID, err)
	//}
	setup.secretStore.secrets.Range(func(key, value interface{}) bool {
		t.Logf("secretStore: secrets %s", key)
		return true
	})
	t.Log("22222222")
	waitForNotificationToProceed(t, notifyChan, "notify push secret 1")
	t.Log("33333333")
	conn.Close()
	time.Sleep(time.Second * 5)
	setup.secretStore.secrets.Range(func(key, value interface{}) bool {
		t.Logf("secretStore: secrets %s", key)
		return true
	})

	conn, stream = createSDSStream(t, setup.socket, fakeToken1)
	go testSDSIngressStreamCache(stream, InValidProxyID, notifyChan, conn)
	// verify that the first SDS request sent by two streams do not hit cache.
	waitForStreamSecretCacheCheck(t, setup.secretStore, false, 1)

	t.Log("111111111")
	t.Logf("sdsClient %v ",len(sdsClients))
	for key, val := range sdsClients {
		t.Logf("key is : %v, value is : %v", key,val)
	}
	//conID := getClientConID(ValidProxyID)
	t.Log(getClientConID(ValidProxyID))
	t.Log(getClientConID(InValidProxyID))
	//if err := NotifyProxy(cache.ConnKey{ConnectionID: conID, ResourceName: testResourceName},
	//	setup.generatePushSecret(conID, fakeToken1)); err != nil {
	//	t.Fatalf("failed to send push notification to proxy %q: %v", conID, err)
	//}
	setup.secretStore.secrets.Range(func(key, value interface{}) bool {
		t.Logf("secretStore: secrets %s", key)
		return true
	})
	t.Log("22222222")
	waitForNotificationToProceed(t, notifyChan, "notify push secret 1")
	t.Log("33333333")
	conn.Close()
	time.Sleep(time.Second * 5)
	setup.secretStore.secrets.Range(func(key, value interface{}) bool {
		t.Logf("secretStore: secrets %s", key)
		return true
	})
	//go testSDSIngressStreamCache(stream, InValidProxyID, notifyChan, conn)

}

// waitForSecretCacheCheck wait until cache hit or cache miss meets expected value and return. Or
// return directly on timeout.
func waitForStreamSecretCacheCheck(t *testing.T, mss *mockIngressGatewaySecretStore, expectCacheHit bool, expectValue int) {
	waitTimeout := 5 * time.Second
	checkMetric := "cache hit"
	if !expectCacheHit {
		checkMetric = "cache miss"
	}
	realVal := 0
	start := time.Now()
	for {
		if expectCacheHit {
			realVal = mss.SecretCacheHit()
			if realVal == expectValue {
				return
			}
		}
		if !expectCacheHit {
			realVal = mss.SecretCacheMiss()
			if realVal == expectValue {
				return
			}
		}
		if time.Since(start) > waitTimeout {
			t.Fatalf("%s does not meet expected value in %s, expected %d but got %d",
				checkMetric, waitTimeout.String(), expectValue, realVal)
			return
		}
		time.Sleep(1 * time.Second)
	}
}

func testSDSIngressStreamCache(stream sds.SecretDiscoveryService_StreamSecretsClient, proxyID string,
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

type StreamSetup struct {
	t                          *testing.T
	socket                     string
	server                     *Server
	secretStore                *mockIngressGatewaySecretStore
	initialTotalPush           float64
	initialTotalUpdateFailures float64
}

func (s *StreamSetup) waitForSDSReady() error {
	var conErr, streamErr error
	var conn *grpc.ClientConn
	for i := 0; i < 20; i++ {
		if conn, conErr = setupConnection(s.socket); conErr == nil {
			sdsClient := sds.NewSecretDiscoveryServiceClient(conn)
			header := metadata.Pairs(credentialTokenHeaderKey, fakeToken1)
			ctx := metadata.NewOutgoingContext(context.Background(), header)
			if _, streamErr = sdsClient.StreamSecrets(ctx); streamErr == nil {
				return nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("cannot connect SDS server, connErr: %v, streamErr: %v", conErr, streamErr)
}

func (s *StreamSetup) generatePushSecret(conID, token string) *model.SecretItem {
	pushSecret := &model.SecretItem{
		CertificateChain: fakePushCertificateChain,
		PrivateKey:       fakePushPrivateKey,
		ResourceName:     testResourceName,
		Version:          time.Now().Format("01-02 15:04:05.000"),
		Token:            token,
	}
	s.secretStore.secrets.Store(cache.ConnKey{ConnectionID: conID, ResourceName: testResourceName}, pushSecret)
	return pushSecret
}

type mockIngressGatewaySecretStore struct {
	checkToken      bool
	secrets         sync.Map
	mutex           sync.RWMutex
	secretCacheHit  int
	secretCacheMiss int
}

func (ms *mockIngressGatewaySecretStore) SecretCacheHit() int {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	return ms.secretCacheHit
}

func (ms *mockIngressGatewaySecretStore) SecretCacheMiss() int {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	return ms.secretCacheMiss
}

func (ms *mockIngressGatewaySecretStore) GenerateSecret(ctx context.Context, conID, resourceName, token string) (*model.SecretItem, error) {
	if ms.checkToken && token != fakeToken1 && token != fakeToken2 {
		return nil, fmt.Errorf("unexpected token %q", token)
	}

	key := cache.ConnKey{
		ConnectionID: conID,
		ResourceName: resourceName,
	}
	if resourceName == testResourceName {
		s := &model.SecretItem{
			CertificateChain: fakeCertificateChain,
			PrivateKey:       fakePrivateKey,
			ResourceName:     testResourceName,
			Version:          time.Now().Format("01-02 15:04:05.000"),
			Token:            token,
		}
		fmt.Println("Store secret for key: ", key, ". token: ", token)
		ms.secrets.Store(key, s)
		if strings.Contains(conID,"invalid") {
			return s, fmt.Errorf("invalid connection for test")
		}
		return s, nil
	}

	if resourceName == cache.RootCertReqResourceName || strings.HasPrefix(resourceName, "file-root:") {
		s := &model.SecretItem{
			RootCert:     fakeRootCert,
			ResourceName: cache.RootCertReqResourceName,
			Version:      time.Now().Format("01-02 15:04:05.000"),
			Token:        token,
		}
		fmt.Println("Store root cert for key: ", key, ". token: ", token)
		ms.secrets.Store(key, s)
		if strings.Contains(conID,"invalid") {
			return s, fmt.Errorf("invalid connection for test")
		}
		return s, nil
	}

	return nil, fmt.Errorf("unexpected resourceName %q", resourceName)
}

func (ms *mockIngressGatewaySecretStore) SecretExist(conID, spiffeID, token, version string) bool {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	key := cache.ConnKey{
		ConnectionID: conID,
		ResourceName: spiffeID,
	}
	val, found := ms.secrets.Load(key)
	if !found {
		fmt.Printf("cannot find secret %v in cache\n", key)
		ms.secretCacheMiss++
		return false
	}
	cs := val.(*model.SecretItem)
	fmt.Println("key is: ", key, ". Token: ", cs.Token)
	if spiffeID != cs.ResourceName {
		fmt.Printf("resource name not match: %s vs %s\n", spiffeID, cs.ResourceName)
		ms.secretCacheMiss++
		return false
	}
	if token != cs.Token {
		fmt.Printf("token does not match %+v vs %+v\n", token, cs.Token)
		ms.secretCacheMiss++
		return false
	}
	if version != cs.Version {
		fmt.Printf("version does not match %s vs %s\n", version, cs.Version)
		ms.secretCacheMiss++
		return false
	}
	fmt.Printf("requested secret matches cache\n")
	ms.secretCacheHit++
	return true
}

func (ms *mockIngressGatewaySecretStore) DeleteSecret(conID, resourceName string) {
	key := cache.ConnKey{
		ConnectionID: conID,
		ResourceName: resourceName,
	}
	fmt.Printf("mockIngressGatewaySecretStore,conId: %s, resourceName: %s", conID, resourceName)
	ms.secrets.Delete(key)
}

func (ms *mockIngressGatewaySecretStore) ShouldWaitForIngressGatewaySecret(connectionID, resourceName, token string, fileMountedCertsOnly bool) bool {
	return false
}

// StartTest starts SDS server and checks SDS connectivity.
func StartStreamTest(t *testing.T) *StreamSetup {
	s := &StreamSetup{t: t}
	// reset connectionNumber since since its value is kept in memory for all unit test cases lifetime,
	// reset since it may be updated in other test case.
	atomic.StoreInt64(&connectionNumber, 0)

	s.socket = fmt.Sprintf("/tmp/gotest%s.sock", string(uuid.NewUUID()))
	s.server, s.secretStore = createStreamSDSServer(t, s.socket)

	if err := s.waitForSDSReady(); err != nil {
		t.Fatalf("fail to start SDS server: %v", err)
	}

	// Get initial SDS push stats.
	initialTotalPush, err := util.GetMetricsCounterValue("total_pushes")
	if err != nil {
		t.Fatalf("fail to get initial value from metric totalPush: %v", err)
	}
	initialTotalUpdateFailures, err := util.GetMetricsCounterValue("total_secret_update_failures")
	if err != nil {
		t.Fatalf("fail to get initial value from metric totalSecretUpdateFailureCounts: %v", err)
	}
	s.initialTotalPush = initialTotalPush
	s.initialTotalUpdateFailures = initialTotalUpdateFailures

	return s
}

func createStreamSDSServer(t *testing.T, socket string) (*Server, *mockIngressGatewaySecretStore) {
	arg := Options{
		EnableIngressGatewaySDS: false,
		EnableWorkloadSDS:       true,
		RecycleInterval:         100 * time.Second,
		WorkloadUDSPath:         socket,
	}
	st := &mockIngressGatewaySecretStore{
		checkToken: false,
	}
	server, err := NewServer(arg, st, nil)
	if err != nil {
		t.Fatalf("failed to start grpc server for sds: %v", err)
	}
	return server, st
}
