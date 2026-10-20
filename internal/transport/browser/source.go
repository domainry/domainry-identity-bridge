package browser

import _ "embed"

// Source is the dependency-free browser adapter distributed with
// the module. Provider URLs and credentials are always discovered/configured.
//
//go:embed web/client.js
var Source string
