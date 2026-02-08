// Permissions module tests
import { describe, it, expect } from 'vitest';
import {
  PERMISSION_LEVELS,
  DEFAULT_PERMISSIONS,
  FULL_PERMISSIONS,
  orgGrants
} from '../db/index.js';

describe('Permission Levels', () => {
  it('should have all expected permission levels', () => {
    expect(PERMISSION_LEVELS).toEqual(['read', 'list', 'write', 'delete', 'admin', 'share']);
  });

  it('should have correct default permissions', () => {
    expect(DEFAULT_PERMISSIONS).toEqual({
      read: true,
      list: false,
      write: false,
      delete: false,
      admin: false,
      share: false
    });
  });

  it('should have correct full permissions', () => {
    expect(FULL_PERMISSIONS).toEqual({
      read: true,
      list: true,
      write: true,
      delete: true,
      admin: true,
      share: true
    });
  });
});

describe('normalizePermissions', () => {
  const { normalizePermissions } = orgGrants;

  it('should return default permissions when input is null/undefined', () => {
    expect(normalizePermissions(null)).toEqual(DEFAULT_PERMISSIONS);
    expect(normalizePermissions(undefined)).toEqual(DEFAULT_PERMISSIONS);
  });

  it('should normalize object permissions', () => {
    const input = { read: true, write: true };
    const result = normalizePermissions(input);
    expect(result).toEqual({
      read: true,
      list: false,
      write: true,
      delete: false,
      admin: false,
      share: false
    });
  });

  it('should convert array permissions to object', () => {
    const input = ['read', 'write', 'delete'];
    const result = normalizePermissions(input);
    expect(result).toEqual({
      read: true,
      list: false,
      write: true,
      delete: true,
      admin: false,
      share: false
    });
  });

  it('should handle empty array', () => {
    const input = [];
    const result = normalizePermissions(input);
    expect(result).toEqual(DEFAULT_PERMISSIONS);
  });

  it('should ignore invalid permissions in array', () => {
    const input = ['read', 'invalid', 'write'];
    const result = normalizePermissions(input);
    expect(result.read).toBe(true);
    expect(result.write).toBe(true);
    expect(result.invalid).toBeUndefined();
  });

  it('should convert truthy values to boolean', () => {
    const input = { read: 1, write: 'yes', delete: 0, admin: '' };
    const result = normalizePermissions(input);
    expect(result.read).toBe(true);
    expect(result.write).toBe(true);
    expect(result.delete).toBe(false);
    expect(result.admin).toBe(false);
  });
});

describe('hasPermission', () => {
  const { hasPermission } = orgGrants;

  it('should return false for null grant', () => {
    expect(hasPermission(null, 'read')).toBe(false);
  });

  it('should return false for grant without permissions', () => {
    expect(hasPermission({}, 'read')).toBe(false);
  });

  it('should check permission from object', () => {
    const grant = { permissions: { read: true, write: false } };
    expect(hasPermission(grant, 'read')).toBe(true);
    expect(hasPermission(grant, 'write')).toBe(false);
    expect(hasPermission(grant, 'delete')).toBe(false);
  });

  it('should parse JSON string permissions', () => {
    const grant = { permissions: '{"read": true, "write": true}' };
    expect(hasPermission(grant, 'read')).toBe(true);
    expect(hasPermission(grant, 'write')).toBe(true);
    expect(hasPermission(grant, 'delete')).toBe(false);
  });
});

describe('hasAnyPermission', () => {
  const { hasAnyPermission } = orgGrants;

  it('should return true if any permission is granted', () => {
    const grant = { permissions: { read: true, write: false, delete: false } };
    expect(hasAnyPermission(grant, ['read', 'write'])).toBe(true);
    expect(hasAnyPermission(grant, ['write', 'delete'])).toBe(false);
  });

  it('should return false for empty permission list', () => {
    const grant = { permissions: { read: true } };
    expect(hasAnyPermission(grant, [])).toBe(false);
  });
});

describe('hasAllPermissions', () => {
  const { hasAllPermissions } = orgGrants;

  it('should return true only if all permissions are granted', () => {
    const grant = { permissions: { read: true, write: true, delete: false } };
    expect(hasAllPermissions(grant, ['read', 'write'])).toBe(true);
    expect(hasAllPermissions(grant, ['read', 'write', 'delete'])).toBe(false);
  });

  it('should return true for empty permission list', () => {
    const grant = { permissions: { read: true } };
    expect(hasAllPermissions(grant, [])).toBe(true);
  });
});

describe('getRequiredPermissionForMethod', () => {
  const { getRequiredPermissionForMethod } = orgGrants;

  it('should return read for GET', () => {
    expect(getRequiredPermissionForMethod('GET')).toBe('read');
    expect(getRequiredPermissionForMethod('get')).toBe('read');
  });

  it('should return write for POST/PUT/PATCH', () => {
    expect(getRequiredPermissionForMethod('POST')).toBe('write');
    expect(getRequiredPermissionForMethod('PUT')).toBe('write');
    expect(getRequiredPermissionForMethod('PATCH')).toBe('write');
    expect(getRequiredPermissionForMethod('post')).toBe('write');
  });

  it('should return delete for DELETE', () => {
    expect(getRequiredPermissionForMethod('DELETE')).toBe('delete');
    expect(getRequiredPermissionForMethod('delete')).toBe('delete');
  });

  it('should return read for unknown methods', () => {
    expect(getRequiredPermissionForMethod('OPTIONS')).toBe('read');
    expect(getRequiredPermissionForMethod('')).toBe('read');
    expect(getRequiredPermissionForMethod(null)).toBe('read');
  });
});
