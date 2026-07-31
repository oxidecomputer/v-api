import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '../test/msw'
import { getSelf } from './self'

const HOST = 'http://vapi.test'

describe('getSelf', () => {
    it('fetches GET /self with a bearer token and returns the camelCased user', async () => {
        let authHeader: string | null = null
        server.use(
            http.get(`${HOST}/self`, ({ request }) => {
                authHeader = request.headers.get('Authorization')
                return HttpResponse.json({
                    info: {
                        id: 'user-1',
                        permissions: ['user:info:r'],
                        groups: ['group-1'],
                        created_at: '2026-01-01T00:00:00Z',
                        updated_at: '2026-01-01T00:00:00Z',
                        deleted_at: null,
                    },
                    providers: [
                        {
                            id: 'provider-1',
                            user_id: 'user-1',
                            provider: 'google',
                            provider_id: 'ext-1',
                            emails: ['user@example.com'],
                            display_names: ['User One'],
                            created_at: '2026-01-01T00:00:00Z',
                            updated_at: '2026-01-01T00:00:00Z',
                            deleted_at: null,
                        },
                    ],
                })
            }),
        )

        const result = await getSelf(HOST, 'tok_abc')

        expect(authHeader).toBe('Bearer tok_abc')
        expect(result.info.id).toBe('user-1')
        expect(result.info.permissions).toEqual(['user:info:r'])
        expect(result.info.groups).toEqual(['group-1'])
        expect(result.providers[0].emails).toEqual(['user@example.com'])
        expect(result.providers[0].displayNames).toEqual(['User One'])
        expect(result.providers[0].providerId).toBe('ext-1')
    })
})
