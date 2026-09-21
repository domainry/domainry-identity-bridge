// Package capability exposes the External Identity Bridge's source-owned,
// deployment-neutral capability contract.
package capability

import "github.com/domainry/domainry-foundation/modulecapability"

type Inputs struct{}

func Open(inputs Inputs) (*modulecapability.StaticBinding, error) {
	return openContract(inputs)
}
