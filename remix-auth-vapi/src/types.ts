/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright Oxide Computer Company
 */

// Shapes below mirror the generic endpoints every v-api based service exposes
// (see v-api/src/endpoints/api_user.rs and v-api/src/authn/jwt.rs). Only the
// `Permission` type parameter varies per consuming service.

export type VApiUserProvider = {
    id: string
    userId: string
    provider: string
    providerId: string
    emails: string[]
    displayNames: string[]
    createdAt: string
    updatedAt: string
    deletedAt?: string | null
}

export type VApiUser<Permission extends string = string> = {
    id: string
    permissions: Permission[]
    groups: string[]
    createdAt: string
    updatedAt: string
    deletedAt?: string | null
}

export type GetUserResponse<Permission extends string = string> = {
    info: VApiUser<Permission>
    providers: VApiUserProvider[]
}

/**
 * Access token claims, per RFC 9068. Note that `scp` is a single
 * space-delimited string on the wire, not an array.
 */
export type VApiAccessTokenClaims = {
    iss: string
    aud: string
    sub: string
    prv: string
    scp: string
    exp: number
    nbf: number
    jti: string
}
