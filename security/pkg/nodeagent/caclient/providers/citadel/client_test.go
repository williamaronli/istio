// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caclient

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	"istio.io/istio/pkg/jwt"
	"istio.io/istio/security/pkg/k8s/tokenreview"
	k8sauth "k8s.io/api/authentication/v1"
	//"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	//ktesting "k8s.io/client-go/testing"

	pb "istio.io/istio/security/proto"
	"istio.io/istio/security/pkg/server/ca/authenticate"

	"k8s.io/client-go/kubernetes/fake"
)

const mockServerAddress = "localhost:0"

var (
	fakeCert  = []string{"foo", "bar"}
	fakeToken = "Bearer fakeToken"
	validToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjdyWTN1bGdTOHpCQ1lscHNpQlJsalBWNVJFaFc2M0VTcHdtWVdnOTY2UDQifQ.eyJhdWQiOlsiaXN0aW8tY2EiXSwiZXhwIjoxNTk0OTk1MDY0LCJpYXQiOjE1OTQ5NTE4NjQsImlzcyI6Imt1YmVybmV0ZXMuZGVmYXVsdC5zdmMiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6InRlc3RpbmciLCJwb2QiOnsibmFtZSI6Imh0dHBiaW4tNWQ1ZmNmOWZmZi13NzZuMiIsInVpZCI6ImVmMDVjOGNlLWY1OTMtNDBhYS04MTFmLTk4Mjg5ODYzODBjYyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiaHR0cGJpbiIsInVpZCI6IjZkZTcyNjVlLTZiNDktNGZlNC1hZjc5LTdmNjdmYjA1ZTQ5NyJ9fSwibmJmIjoxNTk0OTUxODY0LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6dGVzdGluZzpodHRwYmluIn0.ADxhSLZM4KX0f9CLIeIGwllbTPMbwVDKMuvoVT7PSZHqmnl0aTr23bXmranf75HtRbuQwck7z-0KMFmAIG9xr9ZetNVN7kVgHlNkf2O2ozCvc91t2LWJktO91CsMO2cN0drJ3db-GOFDpjgQd5PQKRo5zkfEK4vpfQ-Z9nyq_X0s5dhGobDw1YD9NO72CuV0buX2hr0mPwngq81K_vX3-6qkrQzmkRMjPAjvtxwrTUgAnWCNyjwuhyydALpK3qQiVLzelhpIYDI7OUK2JNzQrzrqBOkHYoFb3edJiTS_Hmsf9I4FyPapt0W-TlgTj8jLFl9Q3h4EfjS23IYUqGOcOg"
)

type mockCAServer struct {
	Certs []string
	Err   error
}

func (ca *mockCAServer) CreateCertificate(ctx context.Context, in *pb.IstioCertificateRequest) (*pb.IstioCertificateResponse, error) {
	if ca.Err == nil {
		return &pb.IstioCertificateResponse{CertChain: ca.Certs}, nil
	}
	return nil, ca.Err
}

func TestCitadelClient(t *testing.T) {
	testCases := map[string]struct {
		server       mockCAServer
		expectedCert []string
		expectedErr  string
	}{
		"Valid certs": {
			server:       mockCAServer{Certs: fakeCert, Err: nil},
			expectedCert: fakeCert,
			expectedErr:  "",
		},
		"Error in response": {
			server:       mockCAServer{Certs: nil, Err: fmt.Errorf("test failure")},
			expectedCert: nil,
			expectedErr:  "rpc error: code = Unknown desc = test failure",
		},
		"Empty response": {
			server:       mockCAServer{Certs: []string{}, Err: nil},
			expectedCert: nil,
			expectedErr:  "invalid response cert chain",
		},
	}

	for id, tc := range testCases {
		// create a local grpc server
		s := grpc.NewServer()
		defer s.Stop()
		lis, err := net.Listen("tcp", mockServerAddress)
		if err != nil {
			t.Fatalf("Test case [%s]: failed to listen: %v", id, err)
		}

		go func() {
			pb.RegisterIstioCertificateServiceServer(s, &tc.server)
			if err := s.Serve(lis); err != nil {
				t.Logf("Test case [%s]: failed to serve: %v", id, err)
			}
		}()

		// The goroutine starting the server may not be ready, results in flakiness.
		time.Sleep(1 * time.Second)

		cli, err := NewCitadelClient(lis.Addr().String(), false, nil, "")
		if err != nil {
			t.Errorf("Test case [%s]: failed to create ca client: %v", id, err)
		}

		resp, err := cli.CSRSign(context.Background(), "12345678-1234-1234-1234-123456789012", []byte{01}, fakeToken, 1)
		if err != nil {
			if err.Error() != tc.expectedErr {
				t.Errorf("Test case [%s]: error (%s) does not match expected error (%s)", id, err.Error(), tc.expectedErr)
			}
		} else {
			if tc.expectedErr != "" {
				t.Errorf("Test case [%s]: expect error: %s but got no error", id, tc.expectedErr)
			} else if !reflect.DeepEqual(resp, tc.expectedCert) {
				t.Errorf("Test case [%s]: resp: got %+v, expected %v", id, resp, tc.expectedCert)
			}
		}
	}
}

type mockTokenCAServer struct {
	Certs []string
	Err   error
}

func (ca *mockTokenCAServer) CreateCertificate(ctx context.Context, in *pb.IstioCertificateRequest) (*pb.IstioCertificateResponse, error) {

	//token: "bearer-token",
	//	metadata: metadata.MD{
	//	"clusterid": []string{primaryCluster},
	//	"authorization": []string{
	//		"Basic callername",
	//	},
	//},
	//jwtPolicy:      jwt.PolicyFirstParty,
	//		expectedID:     fmt.Sprintf(identityTemplate, "example.com", "default", "example-pod-sa"),
	//		expectedErrMsg: "",

	fmt.Printf("SSSSSSSSSSSS-=======\n")
	fmt.Printf("SSSSSSSSSSSS-=======\n")
	fmt.Printf("SSSSSSSSSSSS-=======\n")
	client := fake.NewSimpleClientset()
	tokenReview := &k8sauth.TokenReview{
		Spec: k8sauth.TokenReviewSpec{
			Token: validToken,
		},
	}
	tokenReview.Spec.Audiences = []string{tokenreview.DefaultAudience}
	tokenReview.Status.Audiences = []string{}
	tokenReview.Status.Authenticated = true
	tokenReview.Status.User = k8sauth.UserInfo{
		Username: "system:serviceaccount:default:example-pod-sa",
		Groups:   []string{"system:serviceaccounts"},
	}
	remoteKubeClientGetter := func(clusterID string) kubernetes.Interface {
			//client := fake.NewSimpleClientset()
			//	client.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
			//		return true, tokenReview, nil
			//	})
		return nil
	}
	authenticator := authenticate.NewKubeJWTAuthenticator(client, "Kubernetes", remoteKubeClientGetter, "example.com", jwt.PolicyFirstParty)
	_, err := authenticator.Authenticate(ctx)
	//u, err
	//if len(tc.expectedErrMsg) > 0 {
	//	if err == nil {
	//		//t.Errorf("Case %s: Succeeded. Error expected: %v", id, err)
	//	} else if err.Error() != tc.expectedErrMsg {
	//		t.Errorf("Case %s: Incorrect error message: \n%s\nVS\n%s",
	//			id, err.Error(), tc.expectedErrMsg)
	//	}
	//	return
	//} else if err != nil {
	//	t.Errorf("Case %s: Unexpected Error: %v", id, err)
	//	return
	//}
	if err == nil {
		return &pb.IstioCertificateResponse{CertChain: ca.Certs}, nil
	}

	return nil, err
}

func TestCitadelClientWithDifferentTypeToken(t *testing.T) {
	testCases := map[string]struct {
		server       mockTokenCAServer
		expectedCert []string
		expectedErr  string
		token string
	}{
		"Valid Token": {
			server:       mockTokenCAServer{Certs: fakeCert, Err: nil},
			expectedCert: fakeCert,
			expectedErr:  "",
			token: validToken,
		},
		"Empty Token": {
			server:       mockTokenCAServer{Certs: nil, Err: fmt.Errorf("test failure")},
			expectedCert: nil,
			expectedErr:  "rpc error: code = Unknown desc = test failure",
			token: "",
		},
		"inValid Token": {
			server:       mockTokenCAServer{Certs: []string{}, Err: nil},
			expectedCert: nil,
			expectedErr:  "invalid response cert chain",
			token: fakeToken,
		},
	}

	for id, tc := range testCases {
		// create a local grpc server
		s := grpc.NewServer()
		defer s.Stop()
		lis, err := net.Listen("tcp", mockServerAddress)
		if err != nil {
			t.Fatalf("Test case [%s]: failed to listen: %v", id, err)
		}

		go func() {
			pb.RegisterIstioCertificateServiceServer(s, &tc.server)
			if err := s.Serve(lis); err != nil {
				t.Logf("Test case [%s]: failed to serve: %v", id, err)
			}
		}()

		// The goroutine starting the server may not be ready, results in flakiness.
		time.Sleep(1 * time.Second)

		cli, err := NewCitadelClient(lis.Addr().String(), false, nil, "Kubernetes")
		if err != nil {
			t.Errorf("Test case [%s]: failed to create ca client: %v", id, err)
		}
		t.Logf("id : %+v", id)
		resp, err := cli.CSRSign(context.Background(), "12345678-1234-1234-1234-123456789012", []byte{01}, tc.token, 1)
		t.Logf("resp: %+v, err: %+v", resp, err)
	}
}
