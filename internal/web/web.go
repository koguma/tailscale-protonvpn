package web

import "embed"

//go:embed index.html map.js flags
var FS embed.FS
