import { HttpResponse, http } from 'msw'
import { createMemorySessionStorage } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { server } from '../test/msw'
import {
    InvalidMethod,
    LinkExpiredError,
    MissingRequiredField,
    RemoteError,
    SessionMismatchError,
    VApiMagicLinkStrategy,
    type VApiMagicLinkVerifyParams,
} from './magic-link'

const HOST = 'http://vapi.test'

type TestUser = { id: string; email: string; token: string; returnTo?: string }

function buildStrategy(
    verify: (params: VApiMagicLinkVerifyParams) => Promise<TestUser>,
    overrides: Partial<{
        pendingFlash: { key: string; value: string }
    }> = {},
) {
    return new VApiMagicLinkStrategy<TestUser>(
        {
            storage: createMemorySessionStorage(),
            host: HOST,
            clientSecret: 'client-secret',
            channel: 'login',
            linkExpirationTime: 600,
            pendingPath: '/login?email=sent',
            returnPath: '/auth/magic/callback',
            ...overrides,
        },
        verify,
    )
}

function sendRequest(body: string, headers: Record<string, string> = {}) {
    return new Request('http://app.example.com/auth/magic', {
        method: 'POST',
        headers: { host: 'app.example.com', ...headers },
        body,
    })
}

function returnRequest(query: string, cookie?: string) {
    const headers: Record<string, string> = {}
    if (cookie) headers['Cookie'] = cookie
    return new Request(`http://app.example.com/auth/magic/callback${query}`, {
        method: 'GET',
        headers,
    })
}

const selfResponseBody = {
    info: {
        id: 'user-1',
        permissions: ['user:info:r'],
        groups: [],
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        deleted_at: null,
    },
    providers: [],
}

describe('VApiMagicLinkStrategy', () => {
    beforeEach(() => {
        server.use(
            http.get(`${HOST}/self`, () => HttpResponse.json(selfResponseBody)),
            http.post(`${HOST}/login/magic/login/exchange`, () =>
                HttpResponse.json({ access_token: 'tok-1', expires_in: 600, token_type: 'bearer' }),
            ),
        )
    })

    it('throws InvalidMethod for methods other than GET/POST', async () => {
        const strategy = buildStrategy(async () => ({ id: 'u', email: 'e', token: 't' }))
        const request = new Request('http://app.example.com/auth/magic', { method: 'PUT' })

        await expect(strategy.authenticate(request)).rejects.toBeInstanceOf(InvalidMethod)
    })

    it('throws MissingRequiredField when the send request has no email', async () => {
        const strategy = buildStrategy(async () => ({ id: 'u', email: 'e', token: 't' }))

        await expect(strategy.authenticate(sendRequest(''))).rejects.toBeInstanceOf(MissingRequiredField)
    })

    it('sends a magic link, storing the attempt in session and redirecting to pendingPath', async () => {
        let sentBody: unknown
        server.use(
            http.post(`${HOST}/login/magic/login/send`, async ({ request }) => {
                sentBody = await request.json()
                return HttpResponse.json({ attempt_id: 'attempt-1' })
            }),
        )

        const strategy = buildStrategy(async () => ({ id: 'u', email: 'e', token: 't' }))
        const response = (await strategy
            .authenticate(sendRequest('email=user%40example.com'))
            .catch((e) => e)) as Response

        expect(response).toBeInstanceOf(Response)
        expect(response.status).toBe(302)
        expect(response.headers.get('Location')).toBe('/login?email=sent')
        expect(sentBody).toMatchObject({
            medium: 'email',
            recipient: 'user@example.com',
            secret: 'client-secret',
            expires_in: 600,
            scope: 'user:info:r',
            redirect_uri: 'https://app.example.com/auth/magic/callback',
        })

        const cookie = response.headers.get('Set-Cookie')
        expect(cookie).toBeTruthy()
    })

    it('flashes pendingFlash into the session when configured', async () => {
        server.use(
            http.post(`${HOST}/login/magic/login/send`, () => HttpResponse.json({ attempt_id: 'attempt-1' })),
        )

        const storage = createMemorySessionStorage()
        const strategy = new VApiMagicLinkStrategy<TestUser>(
            {
                storage,
                host: HOST,
                clientSecret: 'client-secret',
                channel: 'login',
                linkExpirationTime: 600,
                pendingPath: '/login?email=sent',
                returnPath: '/auth/magic/callback',
                pendingFlash: { key: 'notice', value: 'check your email' },
            },
            async () => ({ id: 'u', email: 'e', token: 't' }),
        )

        const response = (await strategy
            .authenticate(sendRequest('email=user%40example.com'))
            .catch((e) => e)) as Response
        const cookie = response.headers.get('Set-Cookie')!

        const session = await storage.getSession(cookie)
        expect(session.get('notice')).toBe('check your email')
    })

    it('throws RemoteError when the send request fails upstream', async () => {
        server.use(
            http.post(`${HOST}/login/magic/login/send`, () => HttpResponse.json({ message: 'boom' }, { status: 500 })),
        )

        const strategy = buildStrategy(async () => ({ id: 'u', email: 'e', token: 't' }))

        await expect(
            strategy.authenticate(sendRequest('email=user%40example.com')),
        ).rejects.toBeInstanceOf(RemoteError)
    })

    it('wraps a missing host header as RemoteError (from within the send try-block)', async () => {
        const strategy = buildStrategy(async () => ({ id: 'u', email: 'e', token: 't' }))
        const request = new Request('http://app.example.com/auth/magic', {
            method: 'POST',
            body: 'email=user%40example.com',
        })

        await expect(strategy.authenticate(request)).rejects.toBeInstanceOf(RemoteError)
    })

    it('throws an Error when the return request is missing the code param', async () => {
        const strategy = buildStrategy(async () => ({ id: 'u', email: 'e', token: 't' }))

        await expect(strategy.authenticate(returnRequest(''))).rejects.toThrow('Missing code parameter')
    })

    it('throws SessionMismatchError when the return request has no matching session', async () => {
        const strategy = buildStrategy(async () => ({ id: 'u', email: 'e', token: 't' }))

        await expect(strategy.authenticate(returnRequest('?code=abc'))).rejects.toBeInstanceOf(
            SessionMismatchError,
        )
    })

    it('throws LinkExpiredError when the exchange fails with a 4xx', async () => {
        server.use(
            http.post(`${HOST}/login/magic/login/exchange`, () =>
                HttpResponse.json({ message: 'expired' }, { status: 400 }),
            ),
        )

        const storage = createMemorySessionStorage()
        const session = await storage.getSession()
        session.set('auth:v-ml:attempt', 'attempt-1')
        session.set('auth:v-ml:email', 'user@example.com')
        const cookie = await storage.commitSession(session)

        const strategy = new VApiMagicLinkStrategy<TestUser>(
            {
                storage,
                host: HOST,
                clientSecret: 'client-secret',
                channel: 'login',
                linkExpirationTime: 600,
                pendingPath: '/login?email=sent',
                returnPath: '/auth/magic/callback',
            },
            async () => ({ id: 'u', email: 'e', token: 't' }),
        )

        await expect(strategy.authenticate(returnRequest('?code=abc', cookie))).rejects.toBeInstanceOf(
            LinkExpiredError,
        )
    })

    it('throws RemoteError when the exchange fails with a 5xx', async () => {
        server.use(
            http.post(`${HOST}/login/magic/login/exchange`, () =>
                HttpResponse.json({ message: 'down' }, { status: 500 }),
            ),
        )

        const storage = createMemorySessionStorage()
        const session = await storage.getSession()
        session.set('auth:v-ml:attempt', 'attempt-1')
        session.set('auth:v-ml:email', 'user@example.com')
        const cookie = await storage.commitSession(session)

        const strategy = new VApiMagicLinkStrategy<TestUser>(
            {
                storage,
                host: HOST,
                clientSecret: 'client-secret',
                channel: 'login',
                linkExpirationTime: 600,
                pendingPath: '/login?email=sent',
                returnPath: '/auth/magic/callback',
            },
            async () => ({ id: 'u', email: 'e', token: 't' }),
        )

        await expect(strategy.authenticate(returnRequest('?code=abc', cookie))).rejects.toBeInstanceOf(
            RemoteError,
        )
    })

    it('throws RemoteError when fetching the user (/self) fails', async () => {
        server.use(http.get(`${HOST}/self`, () => HttpResponse.json({ message: 'down' }, { status: 500 })))

        const storage = createMemorySessionStorage()
        const session = await storage.getSession()
        session.set('auth:v-ml:attempt', 'attempt-1')
        session.set('auth:v-ml:email', 'user@example.com')
        const cookie = await storage.commitSession(session)

        const strategy = new VApiMagicLinkStrategy<TestUser>(
            {
                storage,
                host: HOST,
                clientSecret: 'client-secret',
                channel: 'login',
                linkExpirationTime: 600,
                pendingPath: '/login?email=sent',
                returnPath: '/auth/magic/callback',
            },
            async () => ({ id: 'u', email: 'e', token: 't' }),
        )

        await expect(strategy.authenticate(returnRequest('?code=abc', cookie))).rejects.toBeInstanceOf(
            RemoteError,
        )
    })

    it('completes a full send -> return round trip, threading returnTo and calling verify once', async () => {
        server.use(
            http.post(`${HOST}/login/magic/login/send`, () => HttpResponse.json({ attempt_id: 'attempt-1' })),
        )

        const verify = vi.fn(async (params: VApiMagicLinkVerifyParams) => ({
            id: params.user.info.id,
            email: params.email,
            token: params.token,
            returnTo: params.returnTo,
        }))
        const storage = createMemorySessionStorage()
        const strategy = new VApiMagicLinkStrategy<TestUser>(
            {
                storage,
                host: HOST,
                clientSecret: 'client-secret',
                channel: 'login',
                linkExpirationTime: 600,
                pendingPath: '/login?email=sent',
                returnPath: '/auth/magic/callback',
            },
            verify,
        )

        const sendResponse = (await strategy
            .authenticate(sendRequest('email=user%40example.com&returnTo=%2Fdashboard'))
            .catch((e) => e)) as Response
        const cookie = sendResponse.headers.get('Set-Cookie')!

        const user = await strategy.authenticate(returnRequest('?code=abc', cookie))

        expect(user).toEqual({
            id: 'user-1',
            email: 'user@example.com',
            token: 'tok-1',
            returnTo: '/dashboard',
        })
        expect(verify).toHaveBeenCalledTimes(1)
        expect(verify).toHaveBeenCalledWith(
            expect.objectContaining({
                attemptId: 'attempt-1',
                email: 'user@example.com',
                token: 'tok-1',
                returnTo: '/dashboard',
            }),
        )
    })

    it('uses http:// for the redirect URI when the host is localhost', async () => {
        let sentBody: any
        server.use(
            http.post(`${HOST}/login/magic/login/send`, async ({ request }) => {
                sentBody = await request.json()
                return HttpResponse.json({ attempt_id: 'attempt-1' })
            }),
        )

        const strategy = buildStrategy(async () => ({ id: 'u', email: 'e', token: 't' }))
        const request = new Request('http://localhost:3000/auth/magic', {
            method: 'POST',
            headers: { host: 'localhost:3000' },
            body: 'email=user%40example.com',
        })

        await strategy.authenticate(request).catch(() => undefined)

        expect(sentBody.redirect_uri).toBe('http://localhost:3000/auth/magic/callback')
    })
})
