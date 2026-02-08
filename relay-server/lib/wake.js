import axios from 'axios';

const AGENT_SERVER_URL = process.env.AGENT_SERVER_URL || 'http://localhost:4000';
const AGENT_SERVER_TOKEN = process.env.AGENT_SERVER_TOKEN;

if (!AGENT_SERVER_TOKEN) {
  throw new Error(
    'AGENT_SERVER_TOKEN environment variable is required. ' +
    'Generate a secure token and set it in your environment.'
  );
}

/**
 * Wake a hibernated container
 * Called when a message arrives for a hibernated destination
 */
export async function wakeContainer(userId) {
  try {
    const response = await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/wake`,
      {},
      {
        headers: { 'x-auth-token': AGENT_SERVER_TOKEN },
        timeout: 30000 // 30 second timeout for container wake
      }
    );
    return { success: true, data: response.data };
  } catch (err) {
    console.error(`[wake] Failed to wake container ${userId.slice(0, 8)}: ${err.message}`);
    return { success: false, error: err.message };
  }
}

/**
 * Check if a container is hibernated
 */
export async function getContainerStatus(userId) {
  try {
    const response = await axios.get(
      `${AGENT_SERVER_URL}/api/containers/${userId}/status`,
      {
        headers: { 'x-auth-token': AGENT_SERVER_TOKEN },
        timeout: 5000
      }
    );
    return response.data;
  } catch (err) {
    console.error(`[wake] Failed to get container status: ${err.message}`);
    return { status: 'unknown', error: err.message };
  }
}

export { AGENT_SERVER_URL, AGENT_SERVER_TOKEN };
