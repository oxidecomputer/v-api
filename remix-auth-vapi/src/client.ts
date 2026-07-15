/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright Oxide Computer Company
 */

// v-api serializes request/response bodies with snake_case field names.
// Generated per-service SDKs (e.g. @oxide/turnstile.ts) convert to/from
// camelCase at the client boundary; we do the same here so this package
// doesn't need a generated SDK at all.

const camelToSnake = (s: string) => s.replace(/[A-Z]/g, (l) => '_' + l.toLowerCase())
const snakeToCamel = (s: string) => s.replace(/_./g, (l) => l[1]!.toUpperCase())

const isObjectOrArray = (v: unknown): v is object => typeof v === 'object' && v !== null

const mapKeys = (kf: (k: string) => string) =>
    function transform(o: unknown): unknown {
        if (Array.isArray(o)) return o.map(transform)
        if (!isObjectOrArray(o)) return o
        return Object.fromEntries(
            Object.entries(o as Record<string, unknown>).map(([k, v]) => [kf(k), transform(v)]),
        )
    }

const snakeify = mapKeys(camelToSnake)
const camelize = mapKeys(snakeToCamel)

export class VApiRequestError extends Error {
    constructor(
        public readonly status: number,
        public readonly body: unknown,
    ) {
        super(
            (body as { message?: string } | undefined)?.message
                ?? `v-api request failed with status ${status}`,
        )
    }
}

export async function vApiRequest<T>(
    host: string,
    path: string,
    options: { method: 'GET' | 'POST'; body?: unknown; token?: string },
): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (options.body !== undefined) headers['Content-Type'] = 'application/json'
    if (options.token) headers['Authorization'] = `Bearer ${options.token}`

    const response = await fetch(new URL(path, host), {
        method: options.method,
        headers,
        body: options.body !== undefined ? JSON.stringify(snakeify(options.body)) : undefined,
    })

    const text = await response.text()
    const json = text.length > 0 ? camelize(JSON.parse(text)) : undefined

    if (!response.ok) {
        throw new VApiRequestError(response.status, json)
    }

    return json as T
}
