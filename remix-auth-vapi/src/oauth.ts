/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright Oxide Computer Company
 */

import { OAuth2Strategy } from 'remix-auth-oauth2'
import { Strategy } from 'remix-auth/strategy'

/** Providers v-api ships OAuth code-flow support for out of the box. */
export type VApiOAuthProvider = 'google' | 'github' | 'zendesk'

export type VApiOAuthStrategyOptions<
    Provider extends string = VApiOAuthProvider,
    Scope extends string = string,
> = {
    /**
     * Name this strategy is registered under with the remix-auth `Authenticator`.
     * @default `v-api-${remoteProvider}`
     */
    name?: string
    /** Base URL of the v-api based service to authenticate against. */
    host: string
    clientId: string
    clientSecret: string
    redirectURI: string
    remoteProvider: Provider
    /**
     * @default ["user:info:r"]
     */
    scopes?: Scope[]
    /**
     * Custom host for the authorization endpoint. Overrides `host` when
     * constructing the authorization URL.
     * @default host
     */
    authorizationHost?: string
    /**
     * Custom host for the token endpoint. Overrides `host` when
     * constructing the token URL.
     * @default host
     */
    tokenHost?: string
}

export type ExpiringUser = {
    expiresAt: Date
}

export type VApiVerifyCallback<T> = Strategy.VerifyFunction<T, OAuth2Strategy.VerifyOptions>

export class VApiOAuthStrategy<User extends ExpiringUser> extends OAuth2Strategy<User> {
    public name: string
    protected readonly userInfoUrl: string
    protected readonly host: string

    constructor(
        {
            host,
            clientId,
            clientSecret,
            redirectURI,
            remoteProvider,
            scopes,
            authorizationHost,
            tokenHost,
            name,
        }: VApiOAuthStrategyOptions,
        verify: VApiVerifyCallback<User>,
    ) {
        super(
            {
                clientId,
                clientSecret,
                redirectURI,
                authorizationEndpoint: `${authorizationHost ?? host}/login/oauth/${remoteProvider}/code/authorize`,
                tokenEndpoint: `${tokenHost ?? host}/login/oauth/${remoteProvider}/code/token`,
                scopes: scopes ?? ['user:info:r'],
            },
            verify,
        )
        this.name = name ?? `v-api-${remoteProvider}`
        this.host = host
        this.userInfoUrl = `${host}/self`
    }
}
