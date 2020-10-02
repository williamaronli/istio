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

package successsds

import (
	"fmt"
	"testing"
	"time"

	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/util/retry"
	sdsTest "istio.io/istio/security/pkg/nodeagent/test"
)

func TestProxySDS(t *testing.T) {
	setup := sdsTest.SetupTest(t, env.SDSTest)
	defer setup.TearDown()

	setup.StartProxy(t)
	retry.UntilSuccessOrFail(t, func() error {
		for i := 0; i < 10; i++ {
			code, _, err := env.HTTPGet(fmt.Sprintf("http://localhost:%d/echo", setup.OutboundListenerPort))
			if err != nil {
				return fmt.Errorf("Failed in request: %v", err)
			}
			if code != 200 {
				return fmt.Errorf("Unexpected status code: %d", code)
			}
		}
		return nil
	}, retry.Delay(1*time.Second), retry.Timeout(20*time.Second))
}