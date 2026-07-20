import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '../test/msw'
import { VApiRequestError, vApiRequest } from './client'

const HOST = 'http://vapi.test'

describe('vApiRequest', () => {
    it('sends a snake_case body converted from a camelCase input object', async () => {
        let received: unknown
        server.use(
            http.post(`${HOST}/login/magic/login/send`, async ({ request }) => {
                received = await request.json()
                return HttpResponse.json({ attempt_id: 'attempt-1' })
            }),
        )

        const result = await vApiRequest<{ attemptId: string }>(HOST, '/login/magic/login/send', {
            method: 'POST',
            body: { redirectUri: 'https://example.com/callback', expiresIn: 600 },
        })

        expect(received).toEqual({ redirect_uri: 'https://example.com/callback', expires_in: 600 })
        expect(result).toEqual({ attemptId: 'attempt-1' })
    })

    it('omits the Content-Type header and body on GET requests', async () => {
        let contentType: string | null = 'unset'
        server.use(
            http.get(`${HOST}/self`, ({ request }) => {
                contentType = request.headers.get('Content-Type')
                return HttpResponse.json({ ok: true })
            }),
        )

        await vApiRequest(HOST, '/self', { method: 'GET' })

        expect(contentType).toBeNull()
    })

    it('sets an Authorization header only when a token is provided', async () => {
        let authHeader: string | null = 'unset'
        server.use(
            http.get(`${HOST}/self`, ({ request }) => {
                authHeader = request.headers.get('Authorization')
                return HttpResponse.json({ ok: true })
            }),
        )

        await vApiRequest(HOST, '/self', { method: 'GET', token: 'tok_abc' })
        expect(authHeader).toBe('Bearer tok_abc')

        await vApiRequest(HOST, '/self', { method: 'GET' })
        expect(authHeader).toBeNull()
    })

    it('resolves without throwing on an empty response body', async () => {
        server.use(
            http.post(`${HOST}/login/oauth/github/code/token`, () => new HttpResponse(null, { status: 204 })),
        )

        await expect(
            vApiRequest(HOST, '/login/oauth/github/code/token', { method: 'POST', body: {} }),
        ).resolves.toBeUndefined()
    })

    it('throws VApiRequestError with the status and camelCased body on a non-ok response', async () => {
        server.use(
            http.post(`${HOST}/login/magic/login/exchange`, () =>
                HttpResponse.json({ message: 'link expired', request_id: 'req-1' }, { status: 400 }),
            ),
        )

        const err = (await vApiRequest(HOST, '/login/magic/login/exchange', {
            method: 'POST',
            body: {},
        }).catch((e) => e)) as VApiRequestError

        expect(err).toBeInstanceOf(VApiRequestError)
        expect(err.status).toBe(400)
        expect(err.body).toEqual({ message: 'link expired', requestId: 'req-1' })
        expect(err.message).toBe('link expired')
    })

    it('falls back to a generic message when the error body has no message field', async () => {
        server.use(http.get(`${HOST}/self`, () => HttpResponse.json({ error_code: 'boom' }, { status: 500 })))

        const err = (await vApiRequest(HOST, '/self', { method: 'GET' }).catch((e) => e)) as VApiRequestError

        expect(err).toBeInstanceOf(VApiRequestError)
        expect(err.status).toBe(500)
        expect(err.message).toBe('v-api request failed with status 500')
    })
})
