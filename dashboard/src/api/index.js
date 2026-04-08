import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5001',
  timeout: 4000,
})

async function getJson(path) {
  const response = await api.get(path)
  return response.data
}

export function fetchHealth() {
  return getJson('/health')
}

export function fetchStats() {
  return getJson('/api/stats')
}

export function fetchEvents() {
  return getJson('/api/events')
}

export function fetchNodes() {
  return getJson('/api/nodes')
}

export function fetchBlockchainEvents() {
  return getJson('/api/blockchain')
}
