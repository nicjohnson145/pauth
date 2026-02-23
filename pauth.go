package pauth

import "github.com/nicjohnson145/pauth/internal/storage"

type PostgresStoreOpts = storage.PostgresStoreOpts
type PostgresStoreConnectionOpts = storage.PostgresStoreConnectionOpts

// NewPostgresStore creates a PAuth compatible store backed by postgres
var NewPostgresStore = storage.NewPostgresStore

// NewMemoryStore creates a PAuth compatible store backed by memory, best used for quick bench testing
var NewMemoryStore = storage.NewMemoryStore

type MemoryStoreOpts = storage.MemoryStoreOpts
