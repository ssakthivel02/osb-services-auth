import { describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.js';
describe('health', () => { it('returns ok', async () => { const app = buildApp(); const r = await app.inject({ method: 'GET', url: '/health' }); expect(r.statusCode).toBe(200); await app.close(); }); });
