// Usage tracking
import { query } from "./core.js";

export const usage = {
  async record(userId, inputTokens, outputTokens) {
    await query(
      `INSERT INTO usage (user_id, date, input_tokens, output_tokens, api_calls)
       VALUES ($1, CURRENT_DATE, $2, $3, 1)
       ON CONFLICT (user_id, date)
       DO UPDATE SET
         input_tokens = usage.input_tokens + $2,
         output_tokens = usage.output_tokens + $3,
         api_calls = usage.api_calls + 1`,
      [userId, inputTokens, outputTokens],
    );
  },

  async getForUser(userId, days = 30) {
    if (typeof days !== "number" || !Number.isFinite(days) || days < 0) {
      throw new Error("days must be a non-negative number");
    }
    const res = await query(
      `SELECT * FROM usage WHERE user_id = $1 AND date > NOW() - ($2 * INTERVAL '1 day') ORDER BY date DESC`,
      [userId, days],
    );
    return res.rows;
  },
};
