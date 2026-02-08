// Tenant-scoped query builder for multi-tenant data isolation
// Wave 2 Core Multi-Tenant (Task 2.2)
//
// This module provides utilities to ensure all database queries are properly
// scoped to the current tenant, making it impossible to accidentally query
// across tenant boundaries.

import { query } from "./core.js";

// ============================================================================
// Safety Checks
// ============================================================================

/**
 * Assert that a tenant context exists on the request.
 * Throws an error if req.tenant is missing.
 * @param {object} req - Express request object
 * @param {string} [operation] - Optional operation name for error message
 * @throws {Error} If tenant context is missing
 */
export function assertTenantContext(req, operation = "query") {
  if (!req || !req.tenant || !req.tenant.id) {
    const opName = operation ? ` for ${operation}` : "";
    throw new Error(`Tenant context required${opName}. Ensure tenant middleware is applied.`);
  }
}

/**
 * Validate that a row belongs to the specified tenant.
 * @param {object} row - Database row to validate
 * @param {object} req - Express request object with tenant context
 * @returns {boolean} True if row belongs to tenant
 */
export function validateTenantOwnership(row, req) {
  assertTenantContext(req, "validateTenantOwnership");
  if (!row) {
    return false;
  }
  return row.tenant_id === req.tenant.id;
}

/**
 * Filter an array of rows to only those belonging to the specified tenant.
 * @param {object[]} rows - Array of database rows
 * @param {string} tenantId - Tenant UUID to filter by
 * @returns {object[]} Filtered array
 */
export function filterByTenant(rows, tenantId) {
  if (!tenantId) {
    throw new Error("tenantId is required for filterByTenant");
  }
  if (!Array.isArray(rows)) {
    return [];
  }
  return rows.filter((row) => row && row.tenant_id === tenantId);
}

// ============================================================================
// Query Scoping Functions
// ============================================================================

/**
 * Return an object with the tenant_id filter from req.tenant.
 * Useful for spreading into query parameters.
 * @param {string} table - Table name (for documentation/logging purposes)
 * @param {object} req - Express request object with tenant context
 * @returns {{ tenant_id: string }} Object with tenant_id
 */
export function tenantScoped(table, req) {
  assertTenantContext(req, `tenantScoped(${table})`);
  return {
    tenant_id: req.tenant.id,
  };
}

/**
 * Add tenant_id to a query object (shallow merge).
 * @param {object} queryObj - Query object to extend
 * @param {string} tenantId - Tenant UUID
 * @returns {object} Query object with tenant_id added
 */
export function withTenantId(queryObj, tenantId) {
  if (!tenantId) {
    throw new Error("tenantId is required for withTenantId");
  }
  return {
    ...queryObj,
    tenant_id: tenantId,
  };
}

/**
 * Add tenant_id condition to an existing WHERE clause object.
 * @param {object} whereClause - Existing WHERE conditions
 * @param {object} req - Express request object with tenant context
 * @returns {object} WHERE clause with tenant_id added
 */
export function scopeWhere(whereClause, req) {
  assertTenantContext(req, "scopeWhere");
  return {
    ...whereClause,
    tenant_id: req.tenant.id,
  };
}

// ============================================================================
// ORDER BY Validation (SQL Injection Prevention)
// ============================================================================

/**
 * Regex pattern for valid ORDER BY components.
 * Allows: column names (alphanumeric + underscores), optional table prefix, ASC/DESC
 * Examples: "created_at DESC", "users.name ASC", "id"
 */
const ORDER_BY_COLUMN_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$/;
const ORDER_BY_DIRECTION_PATTERN = /^(ASC|DESC)$/i;

/**
 * Validate and sanitize an ORDER BY clause to prevent SQL injection.
 * Accepts formats like:
 *   - "column_name"
 *   - "column_name DESC"
 *   - "column1 ASC, column2 DESC"
 *   - "table.column ASC"
 *
 * @param {string} orderBy - The ORDER BY clause to validate
 * @returns {string|null} The validated ORDER BY clause, or null if invalid
 * @throws {Error} If orderBy contains invalid characters or format
 */
export function validateOrderBy(orderBy) {
  if (!orderBy || typeof orderBy !== "string") {
    return null;
  }

  const trimmed = orderBy.trim();
  if (!trimmed) {
    return null;
  }

  // Split by comma to handle multiple order clauses
  const clauses = trimmed.split(",").map((c) => c.trim());
  const validatedClauses = [];

  for (const clause of clauses) {
    if (!clause) {
      continue;
    }

    // Split by whitespace to separate column and direction
    const parts = clause.split(/\s+/);

    if (parts.length === 0 || parts.length > 2) {
      throw new Error(`Invalid ORDER BY clause: "${clause}". Expected format: "column [ASC|DESC]"`);
    }

    const column = parts[0];
    const direction = parts[1];

    // Validate column name
    if (!ORDER_BY_COLUMN_PATTERN.test(column)) {
      throw new Error(
        `Invalid ORDER BY column: "${column}". Column names must be alphanumeric with underscores.`,
      );
    }

    // Validate direction if provided
    if (direction) {
      if (!ORDER_BY_DIRECTION_PATTERN.test(direction)) {
        throw new Error(`Invalid ORDER BY direction: "${direction}". Must be ASC or DESC.`);
      }
      validatedClauses.push(`${column} ${direction.toUpperCase()}`);
    } else {
      validatedClauses.push(column);
    }
  }

  if (validatedClauses.length === 0) {
    return null;
  }

  return validatedClauses.join(", ");
}

// ============================================================================
// SQL Builders
// ============================================================================

/**
 * Build a SELECT query with automatic tenant scoping.
 * @param {string} table - Table name
 * @param {string|string[]} columns - Columns to select (* or array of column names)
 * @param {object} req - Express request object with tenant context
 * @param {object} [options] - Additional options
 * @param {object} [options.where] - Additional WHERE conditions (column: value)
 * @param {string} [options.orderBy] - ORDER BY clause (e.g., "created_at DESC")
 * @param {number} [options.limit] - LIMIT value
 * @param {number} [options.offset] - OFFSET value
 * @returns {{ sql: string, params: any[] }} SQL query and parameters
 */
export function buildSelect(table, columns, req, options = {}) {
  assertTenantContext(req, `SELECT from ${table}`);

  const columnList = Array.isArray(columns) ? columns.join(", ") : columns;
  const params = [req.tenant.id];
  let paramIndex = 2;

  let sql = `SELECT ${columnList} FROM ${table} WHERE tenant_id = $1`;

  // Add additional WHERE conditions
  if (options.where) {
    for (const [column, value] of Object.entries(options.where)) {
      if (value === null) {
        sql += ` AND ${column} IS NULL`;
      } else if (value === undefined) {
        // Skip undefined values
        continue;
      } else {
        sql += ` AND ${column} = $${paramIndex}`;
        params.push(value);
        paramIndex++;
      }
    }
  }

  // Add ORDER BY (with SQL injection prevention)
  if (options.orderBy) {
    const validatedOrderBy = validateOrderBy(options.orderBy);
    if (validatedOrderBy) {
      sql += ` ORDER BY ${validatedOrderBy}`;
    }
  }

  // Add LIMIT
  if (options.limit !== undefined) {
    sql += ` LIMIT $${paramIndex}`;
    params.push(options.limit);
    paramIndex++;
  }

  // Add OFFSET
  if (options.offset !== undefined) {
    sql += ` OFFSET $${paramIndex}`;
    params.push(options.offset);
    paramIndex++;
  }

  return { sql, params };
}

/**
 * Build an INSERT query with tenant_id automatically added.
 * @param {string} table - Table name
 * @param {object} data - Data to insert (column: value pairs)
 * @param {object} req - Express request object with tenant context
 * @returns {{ sql: string, params: any[] }} SQL query and parameters
 */
export function buildInsert(table, data, req) {
  assertTenantContext(req, `INSERT into ${table}`);

  // Ensure tenant_id is included and matches context
  const insertData = {
    ...data,
    tenant_id: req.tenant.id,
  };

  const columns = Object.keys(insertData);
  const values = Object.values(insertData);
  const placeholders = columns.map((_, i) => `$${i + 1}`);

  const sql = `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${placeholders.join(", ")}) RETURNING *`;

  return { sql, params: values };
}

/**
 * Build an UPDATE query with tenant scoping (ensures you can only update within your tenant).
 * @param {string} table - Table name
 * @param {object} data - Data to update (column: value pairs)
 * @param {string|object} whereId - ID to match or WHERE conditions object
 * @param {object} req - Express request object with tenant context
 * @returns {{ sql: string, params: any[] }} SQL query and parameters
 */
export function buildUpdate(table, data, whereId, req) {
  assertTenantContext(req, `UPDATE ${table}`);

  const params = [];
  let paramIndex = 1;

  // Build SET clause
  const setClauses = [];
  for (const [column, value] of Object.entries(data)) {
    if (value === undefined) {
      continue;
    } // Skip undefined values
    setClauses.push(`${column} = $${paramIndex}`);
    params.push(value);
    paramIndex++;
  }

  // Always add updated_at if not explicitly set
  if (!data.updated_at && !data.updatedAt) {
    setClauses.push("updated_at = NOW()");
  }

  let sql = `UPDATE ${table} SET ${setClauses.join(", ")} WHERE tenant_id = $${paramIndex}`;
  params.push(req.tenant.id);
  paramIndex++;

  // Add ID or additional WHERE conditions
  if (typeof whereId === "string") {
    sql += ` AND id = $${paramIndex}`;
    params.push(whereId);
    paramIndex++;
  } else if (typeof whereId === "object" && whereId !== null) {
    for (const [column, value] of Object.entries(whereId)) {
      if (value === null) {
        sql += ` AND ${column} IS NULL`;
      } else if (value !== undefined) {
        sql += ` AND ${column} = $${paramIndex}`;
        params.push(value);
        paramIndex++;
      }
    }
  }

  sql += " RETURNING *";

  return { sql, params };
}

/**
 * Build a DELETE query with tenant scoping.
 * @param {string} table - Table name
 * @param {string|object} whereId - ID to match or WHERE conditions object
 * @param {object} req - Express request object with tenant context
 * @returns {{ sql: string, params: any[] }} SQL query and parameters
 */
export function buildDelete(table, whereId, req) {
  assertTenantContext(req, `DELETE from ${table}`);

  const params = [req.tenant.id];
  let paramIndex = 2;

  let sql = `DELETE FROM ${table} WHERE tenant_id = $1`;

  if (typeof whereId === "string") {
    sql += ` AND id = $${paramIndex}`;
    params.push(whereId);
    paramIndex++;
  } else if (typeof whereId === "object" && whereId !== null) {
    for (const [column, value] of Object.entries(whereId)) {
      if (value === null) {
        sql += ` AND ${column} IS NULL`;
      } else if (value !== undefined) {
        sql += ` AND ${column} = $${paramIndex}`;
        params.push(value);
        paramIndex++;
      }
    }
  }

  return { sql, params };
}

// ============================================================================
// Query Execution Helpers
// ============================================================================

/**
 * Execute a query with tenant_id injected as the first parameter.
 * Expects $1 in the SQL to be the tenant_id.
 * @param {string} sql - SQL query with $1 as tenant_id placeholder
 * @param {any[]} params - Additional parameters (tenant_id will be prepended)
 * @param {object} req - Express request object with tenant context
 * @returns {Promise<object>} Query result
 */
export async function queryScoped(sql, params, req) {
  assertTenantContext(req, "queryScoped");
  const allParams = [req.tenant.id, ...params];
  return query(sql, allParams);
}

/**
 * Find a record by ID with tenant isolation.
 * Returns the row only if it belongs to the current tenant.
 * @param {string} table - Table name
 * @param {string} id - Record UUID
 * @param {object} req - Express request object with tenant context
 * @returns {Promise<object|undefined>} Record or undefined
 */
export async function findByIdScoped(table, id, req) {
  assertTenantContext(req, `findByIdScoped(${table})`);

  const res = await query(`SELECT * FROM ${table} WHERE id = $1 AND tenant_id = $2`, [
    id,
    req.tenant.id,
  ]);

  return res.rows[0];
}

/**
 * Check if a record exists within the current tenant.
 * @param {string} table - Table name
 * @param {string} id - Record UUID
 * @param {object} req - Express request object with tenant context
 * @returns {Promise<boolean>} True if record exists in tenant
 */
export async function existsInTenant(table, id, req) {
  assertTenantContext(req, `existsInTenant(${table})`);

  const res = await query(`SELECT 1 FROM ${table} WHERE id = $1 AND tenant_id = $2 LIMIT 1`, [
    id,
    req.tenant.id,
  ]);

  return res.rows.length > 0;
}

/**
 * Count records matching criteria within the current tenant.
 * @param {string} table - Table name
 * @param {object} req - Express request object with tenant context
 * @param {object} [where] - Additional WHERE conditions
 * @returns {Promise<number>} Count of matching records
 */
export async function countScoped(table, req, where = {}) {
  assertTenantContext(req, `countScoped(${table})`);

  const params = [req.tenant.id];
  let paramIndex = 2;
  let sql = `SELECT COUNT(*) FROM ${table} WHERE tenant_id = $1`;

  for (const [column, value] of Object.entries(where)) {
    if (value === null) {
      sql += ` AND ${column} IS NULL`;
    } else if (value !== undefined) {
      sql += ` AND ${column} = $${paramIndex}`;
      params.push(value);
      paramIndex++;
    }
  }

  const res = await query(sql, params);
  return parseInt(res.rows[0].count, 10);
}

/**
 * Execute a SELECT query built by buildSelect.
 * @param {string} table - Table name
 * @param {string|string[]} columns - Columns to select
 * @param {object} req - Express request object with tenant context
 * @param {object} [options] - Query options (see buildSelect)
 * @returns {Promise<object[]>} Array of matching rows
 */
export async function selectScoped(table, columns, req, options = {}) {
  const { sql, params } = buildSelect(table, columns, req, options);
  const res = await query(sql, params);
  return res.rows;
}

/**
 * Execute an INSERT query built by buildInsert.
 * @param {string} table - Table name
 * @param {object} data - Data to insert
 * @param {object} req - Express request object with tenant context
 * @returns {Promise<object>} Inserted row
 */
export async function insertScoped(table, data, req) {
  const { sql, params } = buildInsert(table, data, req);
  const res = await query(sql, params);
  return res.rows[0];
}

/**
 * Execute an UPDATE query built by buildUpdate.
 * @param {string} table - Table name
 * @param {object} data - Data to update
 * @param {string|object} whereId - ID or WHERE conditions
 * @param {object} req - Express request object with tenant context
 * @returns {Promise<object|undefined>} Updated row or undefined
 */
export async function updateScoped(table, data, whereId, req) {
  const { sql, params } = buildUpdate(table, data, whereId, req);
  const res = await query(sql, params);
  return res.rows[0];
}

/**
 * Execute a DELETE query built by buildDelete.
 * @param {string} table - Table name
 * @param {string|object} whereId - ID or WHERE conditions
 * @param {object} req - Express request object with tenant context
 * @returns {Promise<number>} Number of deleted rows
 */
export async function deleteScoped(table, whereId, req) {
  const { sql, params } = buildDelete(table, whereId, req);
  const res = await query(sql, params);
  return res.rowCount;
}

// ============================================================================
// Advanced Query Helpers
// ============================================================================

/**
 * Find all records matching criteria within the current tenant.
 * @param {string} table - Table name
 * @param {object} req - Express request object with tenant context
 * @param {object} [options] - Query options
 * @param {object} [options.where] - WHERE conditions
 * @param {string} [options.orderBy] - ORDER BY clause
 * @param {number} [options.limit] - LIMIT value
 * @param {number} [options.offset] - OFFSET value
 * @returns {Promise<object[]>} Array of matching rows
 */
export async function findAllScoped(table, req, options = {}) {
  return selectScoped(table, "*", req, options);
}

/**
 * Find a single record matching criteria within the current tenant.
 * @param {string} table - Table name
 * @param {object} where - WHERE conditions
 * @param {object} req - Express request object with tenant context
 * @returns {Promise<object|undefined>} Matching row or undefined
 */
export async function findOneScoped(table, where, req) {
  const rows = await selectScoped(table, "*", req, { where, limit: 1 });
  return rows[0];
}

/**
 * Create a tenant-scoped query wrapper for a specific table.
 * Returns an object with common CRUD operations pre-configured for the table.
 * @param {string} table - Table name
 * @returns {object} Object with scoped CRUD operations
 */
export function createScopedTable(table) {
  return {
    /**
     * Find a record by ID within tenant
     * @param {string} id - Record UUID
     * @param {object} req - Request with tenant context
     */
    async findById(id, req) {
      return findByIdScoped(table, id, req);
    },

    /**
     * Check if a record exists within tenant
     * @param {string} id - Record UUID
     * @param {object} req - Request with tenant context
     */
    async exists(id, req) {
      return existsInTenant(table, id, req);
    },

    /**
     * Find all records within tenant
     * @param {object} req - Request with tenant context
     * @param {object} [options] - Query options
     */
    async findAll(req, options = {}) {
      return findAllScoped(table, req, options);
    },

    /**
     * Find one record matching criteria within tenant
     * @param {object} where - WHERE conditions
     * @param {object} req - Request with tenant context
     */
    async findOne(where, req) {
      return findOneScoped(table, where, req);
    },

    /**
     * Count records within tenant
     * @param {object} req - Request with tenant context
     * @param {object} [where] - WHERE conditions
     */
    async count(req, where = {}) {
      return countScoped(table, req, where);
    },

    /**
     * Insert a record within tenant
     * @param {object} data - Data to insert
     * @param {object} req - Request with tenant context
     */
    async create(data, req) {
      return insertScoped(table, data, req);
    },

    /**
     * Update a record within tenant
     * @param {string|object} whereId - ID or WHERE conditions
     * @param {object} data - Data to update
     * @param {object} req - Request with tenant context
     */
    async update(whereId, data, req) {
      return updateScoped(table, data, whereId, req);
    },

    /**
     * Delete a record within tenant
     * @param {string|object} whereId - ID or WHERE conditions
     * @param {object} req - Request with tenant context
     */
    async delete(whereId, req) {
      return deleteScoped(table, whereId, req);
    },

    /**
     * Build a SELECT query (without executing)
     * @param {string|string[]} columns - Columns to select
     * @param {object} req - Request with tenant context
     * @param {object} [options] - Query options
     */
    buildSelect(columns, req, options = {}) {
      return buildSelect(table, columns, req, options);
    },

    /**
     * Build an INSERT query (without executing)
     * @param {object} data - Data to insert
     * @param {object} req - Request with tenant context
     */
    buildInsert(data, req) {
      return buildInsert(table, data, req);
    },

    /**
     * Build an UPDATE query (without executing)
     * @param {object} data - Data to update
     * @param {string|object} whereId - ID or WHERE conditions
     * @param {object} req - Request with tenant context
     */
    buildUpdate(data, whereId, req) {
      return buildUpdate(table, data, whereId, req);
    },

    /**
     * Build a DELETE query (without executing)
     * @param {string|object} whereId - ID or WHERE conditions
     * @param {object} req - Request with tenant context
     */
    buildDelete(whereId, req) {
      return buildDelete(table, whereId, req);
    },
  };
}

// ============================================================================
// Error Classes for Tenant Violations
// ============================================================================

/**
 * Error thrown when a tenant context is required but not present.
 */
export class TenantContextError extends Error {
  constructor(message = "Tenant context required") {
    super(message);
    this.name = "TenantContextError";
    this.code = "TENANT_CONTEXT_REQUIRED";
  }
}

/**
 * Error thrown when a cross-tenant access attempt is detected.
 */
export class TenantIsolationError extends Error {
  constructor(message = "Cross-tenant access denied") {
    super(message);
    this.name = "TenantIsolationError";
    this.code = "TENANT_ISOLATION_VIOLATION";
  }
}

/**
 * Strict version of validateTenantOwnership that throws on violation.
 * @param {object} row - Database row to validate
 * @param {object} req - Express request object with tenant context
 * @throws {TenantIsolationError} If row doesn't belong to tenant
 */
export function requireTenantOwnership(row, req) {
  if (!validateTenantOwnership(row, req)) {
    throw new TenantIsolationError(
      `Record does not belong to tenant ${req.tenant?.id || "(no tenant)"}`,
    );
  }
}
