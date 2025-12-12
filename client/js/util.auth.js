const SESSION_KEY = 'nodecrypt_session';
const API_PREFIX = '/api';

export function getSession() {
	const raw = localStorage.getItem(SESSION_KEY);
	if (!raw) return null;
	try {
		return JSON.parse(raw);
	} catch {
		return null;
	}
}

export function setSession(session) {
	if (!session) {
		localStorage.removeItem(SESSION_KEY);
		return;
	}
	localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession() {
	localStorage.removeItem(SESSION_KEY);
}

async function request(path, options = {}) {
	const res = await fetch(`${API_PREFIX}${path}`, {
		headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
		...options
	});
	const data = await res.json().catch(() => ({}));
	return { ok: res.ok, status: res.status, data };
}

export async function sendEmailCode(email) {
	return request('/auth/send-code', {
		method: 'POST',
		body: JSON.stringify({ email })
	});
}

export async function registerAccount({ username, email, password, code }) {
	const res = await request('/auth/register', {
		method: 'POST',
		body: JSON.stringify({ username, email, password, code })
	});
	if (res.ok && res.data?.token) {
		setSession({
			token: res.data.token,
			userId: res.data.userId,
			username: res.data.username,
			expiresAt: res.data.expiresAt
		});
	}
	return res;
}

export async function loginAccount({ identifier, password }) {
	const res = await request('/auth/login', {
		method: 'POST',
		body: JSON.stringify({ identifier, password })
	});
	if (res.ok && res.data?.token) {
		setSession({
			token: res.data.token,
			userId: res.data.userId,
			username: res.data.username,
			expiresAt: res.data.expiresAt
		});
	}
	return res;
}

export async function fetchHistory({ dialogId, afterId, limit = 50, token }) {
	const headers = {};
	if (token) headers.Authorization = `Bearer ${token}`;
	const url = new URL(`${API_PREFIX}/history`, window.location.origin);
	url.searchParams.set('dialog', dialogId);
	if (afterId) url.searchParams.set('after', afterId);
	url.searchParams.set('limit', limit);
	const res = await fetch(url.toString().replace(window.location.origin, ''), {
		headers
	});
	const data = await res.json().catch(() => ({}));
	return { ok: res.ok, status: res.status, data };
}
