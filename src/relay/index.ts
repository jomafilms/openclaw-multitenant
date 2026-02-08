/**
 * OCMT Mesh Relay Module
 *
 * Provides instant capability revocation enforcement across the mesh network.
 *
 * Components:
 * - BloomFilter: Fast probabilistic lookup for revoked capabilities
 * - RevocationStore: Persistent storage for revocation records
 * - RevocationService: HTTP API for submitting and checking revocations
 * - RelayClient: Container-side client for notifying relay of revocations
 *
 * Trust Model:
 * The relay gains enforcement power by maintaining a revocation blocklist.
 * See docs/mesh/trust-model.md for security analysis.
 *
 * @module relay
 */

// Bloom filter for fast lookup
export {
  BloomFilter,
  computeOptimalSize,
  computeOptimalHashCount,
  createRevocationBloomFilter,
  type BloomFilterConfig,
} from "./bloom-filter.js";

// Revocation storage
export {
  RevocationStore,
  getRevocationStore,
  resetRevocationStore,
  type RevocationRecord,
  type RevocationCheckResult,
} from "./revocation-store.js";

// Revocation service (HTTP API)
export {
  createRevocationService,
  createRevocationMiddleware,
  handleRevocationHttpRequest,
  type RevocationRequest,
  type RevocationResponse,
  type RevocationCheckRequest,
  type RevocationCheckResponse,
} from "./revocation-service.js";

// Container-side client
export {
  RelayClient,
  getRelayClient,
  resetRelayClient,
  type RelayClientConfig,
  type NotifyRevocationParams,
  type NotifyRevocationResult,
  type NotifyKeyRotationParams,
  type KeyRotationResult,
  type RegisterContainerParams,
  type ContainerRegistration,
  type ContainerLookupResult,
  type SendMessageParams,
  type SendMessageResult,
  type PendingMessage,
} from "./client.js";

// Multi-relay client with failover support
export {
  MultiRelayClient,
  getMultiRelayClient,
  resetMultiRelayClient,
  type MultiRelayConfig,
  type RelaySelectionStrategy,
  type RelayHealth,
  type MultiRelayResult,
} from "./multi-relay-client.js";
