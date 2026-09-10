package bridge

import _ "embed"

// BrowserClientSource is the dependency-free browser adapter distributed with
// the module. Provider URLs and credentials are always discovered/configured.
//
//go:embed web/client.js
var BrowserClientSource string
