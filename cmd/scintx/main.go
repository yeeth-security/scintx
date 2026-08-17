package main

import (
	"log"
	"os"

	_ "github.com/yeeth-security/scintx/extensions/policies/all"   // registers policy engines via init()
	_ "github.com/yeeth-security/scintx/extensions/providers/all" // registers providers via init()
	"github.com/yeeth-security/scintx/internal/scintx"
	"github.com/yeeth-security/scintx/internal/server"
)

func main() {
	store := scintx.NewStore()
	emitter := scintx.NewEventEmitter("https://scintx.example", store)

	// Load the default policy engine from the registry.
	// The import of extensions/policies/all triggers init() registration.
	policy, err := scintx.LoadPolicyEngine("default")
	if err != nil {
		log.Fatalf("failed to load policy engine: %v", err)
	}

	orch := scintx.NewOrchestrator(store, policy, emitter)

	// Load all registered providers from the registry.
	// The import of extensions/providers/all triggers init() registration.
	if err := orch.LoadProvidersFromRegistry(); err != nil {
		log.Fatalf("failed to load providers: %v", err)
	}

	log.Printf("SCINTX started: %d provider(s) registered", len(orch.Providers))
	for _, p := range orch.Providers {
		log.Printf("  provider: %s", p.ID())
	}

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