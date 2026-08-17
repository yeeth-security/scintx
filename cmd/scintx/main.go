package main

import (
	"log"
	"os"

	"github.com/yeeth-security/scintx/internal/providers"
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/server"
)

func main() {
	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)
	policy := scintx.DefaultPolicy()
	scintx.SetStoreResultLookup(store.GetResult)
	orch := scintx.NewOrchestrator(store, policy, emitter)

	stub := &providers.StubVulnProvider{ManifestDigest: ""}
	stub.ManifestDigest = stub.Capabilities().ManifestDigest
	orch.RegisterProvider(stub)

	srv := server.New(store, orch, emitter)
	addr := os.Getenv("SCINTX_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("SCINTX listening on %s", addr)
	if err := srv.Start(addr); err != nil {
		log.Fatal(err)
	}
}