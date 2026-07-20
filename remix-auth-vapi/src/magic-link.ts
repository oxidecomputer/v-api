/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright Oxide Computer Company
 */

import type { SessionStorage } from 'react-router'
import { redirect } from 'react-router'
import { Strategy } from 'remix-auth/strategy'

import { VApiRequestError, vApiRequest } from './client'
import { getSelf } from './self'
import type { GetUserResponse } from './types'

export class InvalidMethod extends Error {}
export class MissingRequiredField extends Error {}
export class RemoteError extends Error {}
export class LinkExpiredError extends Error {}
export class SessionMismatchError extends Error {}

type MagicLinkSendResponse = { attemptId: string }
type MagicLinkExchangeResponse = { accessToken: string; expiresIn: number; tokenType: string }

export type VApiMagicLinkStrategyOptions<Scope extends string = string> = {
    /**
     * Name this strategy is registered under with the remix-auth `Authenticator`.
     * @default "v-api-magic-link"
     */
    name?: string
    storage: SessionStorage
    /** Base URL of the v-api based service to authenticate against. */
    host: string
    clientSecret: string
    channel: string
    linkExpirationTime: number
    pendingPath: string
    returnPath: string
    /** If set, flashes this key/value into the session before redirecting to pendingPath. */
    pendingFlash?: { key: string; value: string }
    /**
     * @default ["user:info:r"]
     */
    scope?: Scope[]
}

export type VApiMagicLinkVerifyParams<Permission extends string = string> = {
    attemptId: string
    email: string
    user: GetUserResponse<Permission>
    token: string
    returnTo?: string
}

export class VApiMagicLinkStrategy<
    User,
    Permission extends string = string,
    Scope extends string = string,
> extends Strategy<User, VApiMagicLinkVerifyParams<Permission>> {
    public name: string

    private readonly storage: SessionStorage
    private readonly host: string
    private readonly clientSecret: string
    private readonly channel: string
    private readonly scope: Scope[]
    private readonly linkExpirationTime: number
    private readonly pendingPath: string
    private readonly returnPath: string
    private readonly pendingFlash?: { key: string; value: string }

    private readonly emailField: string = 'email'
    private readonly authnCodeSearchParam: string = 'code'
    private readonly returnToField: string = 'returnTo'

    private readonly sessionAttemptKey: string = 'auth:v-ml:attempt'
    private readonly sessionEmailKey: string = 'auth:v-ml:email'
    private readonly sessionReturnToKey: string = 'auth:v-ml:returnTo'

    protected verify: Strategy.VerifyFunction<User, VApiMagicLinkVerifyParams<Permission>>

    constructor(
        options: VApiMagicLinkStrategyOptions<Scope>,
        verify: Strategy.VerifyFunction<User, VApiMagicLinkVerifyParams<Permission>>,
    ) {
        super(verify)
        this.verify = verify

        this.name = options.name ?? 'v-api-magic-link'
        this.storage = options.storage
        this.host = options.host
        this.pendingPath = options.pendingPath
        this.returnPath = options.returnPath
        this.clientSecret = options.clientSecret
        this.channel = options.channel
        this.scope = options.scope ?? (['user:info:r'] as Scope[])
        this.linkExpirationTime = options.linkExpirationTime
        this.pendingFlash = options.pendingFlash
    }

    public async authenticate(request: Request): Promise<User> {
        if (request.method === 'GET') {
            return await this.handleReturnRequest(request)
        } else if (request.method === 'POST') {
            return await this.handleSendRequest(request)
        } else {
            throw new InvalidMethod(request.method)
        }
    }

    private async handleSendRequest(request: Request): Promise<User> {
        const session = await this.storage.getSession(request.headers.get('Cookie'))

        if (request.method !== 'POST') {
            throw new InvalidMethod(request.method)
        }

        const form = new URLSearchParams(await request.text())
        const email = form.get(this.emailField)
        const returnTo = form.get(this.returnToField)

        if (!email) {
            throw new MissingRequiredField('email')
        }

        try {
            const redirectUri = this.getDomainUrl(request)
            redirectUri.pathname = this.returnPath

            const response = await vApiRequest<MagicLinkSendResponse>(
                this.host,
                `/login/magic/${this.channel}/send`,
                {
                    method: 'POST',
                    body: {
                        medium: 'email',
                        recipient: email,
                        redirectUri: redirectUri.toString(),
                        secret: this.clientSecret,
                        expiresIn: this.linkExpirationTime,
                        scope: this.scope.join(' '),
                    },
                },
            )

            session.set(this.sessionAttemptKey, response.attemptId)
            session.set(this.sessionEmailKey, email)
            if (returnTo) {
                session.set(this.sessionReturnToKey, returnTo)
            }
        } catch (err) {
            console.error('v-api server failed to send magic link email', err)
            throw new RemoteError('Failed to send magic link email')
        }

        if (this.pendingFlash) {
            session.flash(this.pendingFlash.key, this.pendingFlash.value)
        }

        const cookies = await this.storage.commitSession(session)
        throw redirect(this.pendingPath, {
            headers: {
                'Set-Cookie': cookies,
            },
        })
    }

    private async handleReturnRequest(request: Request): Promise<User> {
        const session = await this.storage.getSession(request.headers.get('Cookie'))

        if (request.method !== 'GET') {
            throw new InvalidMethod(request.method)
        }

        const code = new URL(request.url).searchParams.get(this.authnCodeSearchParam)
        if (!code) {
            throw new Error('Missing code parameter')
        }

        const attemptId = session.get(this.sessionAttemptKey)
        if (!attemptId) {
            throw new SessionMismatchError(
                'Missing attemptId in session. This link may not have been intended for the current browser',
            )
        }

        const email = session.get(this.sessionEmailKey)
        if (!email) {
            throw new SessionMismatchError(
                'Missing email in session. This link may not have been intended for the current browser',
            )
        }

        const returnTo: string | undefined = session.get(this.sessionReturnToKey)

        let token: string
        try {
            const exchangeResult = await vApiRequest<MagicLinkExchangeResponse>(
                this.host,
                `/login/magic/${this.channel}/exchange`,
                {
                    method: 'POST',
                    body: {
                        attemptId,
                        recipient: email,
                        secret: code,
                    },
                },
            )

            token = exchangeResult.accessToken
        } catch (err) {
            if (err instanceof VApiRequestError && err.status >= 400 && err.status < 500) {
                throw new LinkExpiredError('Magic link is invalid, expired, or already used')
            }
            console.error('Failed to exchange authentication code of user credentials', err)
            throw new RemoteError('Failed to exchange authentication code of user credentials')
        }

        let user: User
        try {
            const apiUser = await getSelf<Permission>(this.host, token)
            user = await this.verify({ attemptId, email, user: apiUser, token, returnTo })
        } catch (err) {
            console.error('Failed to retrieve user data', err)
            throw new RemoteError('Failed to retrieve user data')
        }

        return user
    }

    private getDomainUrl(request: Request): URL {
        const host = request.headers.get('X-Forwarded-Host') ?? request.headers.get('host')

        if (!host) {
            throw new Error('Could not determine domain URL.')
        }

        const protocol = host.includes('localhost') || host.includes('127.0.0.1')
            ? 'http'
            : request.headers.get('X-Forwarded-Proto') ?? 'https'

        return new URL(`${protocol}://${host}`)
    }
}
