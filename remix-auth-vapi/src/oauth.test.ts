import { describe, expect, it } from 'vitest'

import { VApiOAuthStrategy, type ExpiringUser } from './oauth'

type TestUser = ExpiringUser & { id: string }

const verify = async () => ({ id: 'user-1', expiresAt: new Date() }) as TestUser

const baseOptions = {
    host: 'https://api.example.com',
    clientId: 'client-id',
    clientSecret: 'client-secret',
    redirectURI: 'https://app.example.com/callback',
}

describe('VApiOAuthStrategy', () => {
    it('defaults the strategy name to v-api-{provider}', () => {
        const strategy = new VApiOAuthStrategy({ ...baseOptions, remoteProvider: 'github' }, verify)
        expect(strategy.name).toBe('v-api-github')
    })

    it('accepts an explicit name override', () => {
        const strategy = new VApiOAuthStrategy(
            { ...baseOptions, remoteProvider: 'google', name: 'rfd-google' },
            verify,
        )
        expect(strategy.name).toBe('rfd-google')
    })

    it('builds authorization/token endpoints and userInfoUrl from host', () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const strategy = new VApiOAuthStrategy({ ...baseOptions, remoteProvider: 'google' }, verify) as any

        expect(strategy.options.authorizationEndpoint).toBe(
            'https://api.example.com/login/oauth/google/code/authorize',
        )
        expect(strategy.options.tokenEndpoint).toBe('https://api.example.com/login/oauth/google/code/token')
        expect(strategy.userInfoUrl).toBe('https://api.example.com/self')
    })

    it('honors authorizationHost/tokenHost overrides independently of host', () => {
        const strategy = new VApiOAuthStrategy(
            {
                ...baseOptions,
                remoteProvider: 'google',
                authorizationHost: 'https://auth.example.com',
                tokenHost: 'https://token.example.com',
            },
            verify,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ) as any

        expect(strategy.options.authorizationEndpoint).toBe(
            'https://auth.example.com/login/oauth/google/code/authorize',
        )
        expect(strategy.options.tokenEndpoint).toBe('https://token.example.com/login/oauth/google/code/token')
        // userInfoUrl always follows `host`, not the authorization/token overrides
        expect(strategy.userInfoUrl).toBe('https://api.example.com/self')
    })

    it('defaults scopes to ["user:info:r"] when none are given', () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const strategy = new VApiOAuthStrategy({ ...baseOptions, remoteProvider: 'google' }, verify) as any
        expect(strategy.options.scopes).toEqual(['user:info:r'])
    })
})
