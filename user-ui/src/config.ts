/**
 * Platform configuration.
 * Platform name is configurable via environment variable for rebranding.
 */

// Platform name - can be overridden via VITE_PLATFORM_NAME env var
export const platformName = import.meta.env.VITE_PLATFORM_NAME ?? "OCMT";

// Storage key prefix for localStorage items
export const storagePrefix = "ocmt_";
