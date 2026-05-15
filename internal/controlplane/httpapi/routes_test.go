package httpapi

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
)

// TestEveryAuthenticatedRouteHasMappedAction enforces the BE-0019 invariant:
// every served route that requires authentication must name a catalogued
// policy action, and every public route must name none. It iterates the same
// route table NewHandler registers and folds in openAPIEndpoint, which is
// served too. The moment a future endpoint story registers an authenticated
// route without a mapped action, this test fails CI — there is no way to ship
// an authenticated endpoint the policy engine cannot authorize.
func TestEveryAuthenticatedRouteHasMappedAction(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	endpoints := append(endpointsOf(table), openAPIEndpoint())

	for _, ep := range endpoints {
		ep := ep
		name := ep.Method + " " + ep.Path
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			action := policy.Action(ep.RequiredAction)
			switch {
			case ep.RequiresAuth && ep.RequiredAction == "":
				t.Errorf("%s requires auth but declares no required action", name)
			case ep.RequiresAuth && !policy.Catalogued(action):
				t.Errorf("%s required action %q is not in the policy catalog", name, ep.RequiredAction)
			case !ep.RequiresAuth && ep.RequiredAction != "":
				t.Errorf("%s is public but declares required action %q", name, ep.RequiredAction)
			}
		})
	}
}
