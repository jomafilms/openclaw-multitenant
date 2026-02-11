const MANAGEMENT_SERVER_URL = process.env.MANAGEMENT_SERVER_URL || 'http://localhost:3000';
const MANAGEMENT_API_TOKEN = process.env.MANAGEMENT_API_TOKEN;

async function proxyToManagement(path, options = {}) {
  const url = `${MANAGEMENT_SERVER_URL}${path}`;
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (MANAGEMENT_API_TOKEN) {
    headers['Authorization'] = `Bearer ${MANAGEMENT_API_TOKEN}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Management API error: ${response.status} - ${error}`);
  }

  return response.json();
}

export { proxyToManagement, MANAGEMENT_SERVER_URL };
