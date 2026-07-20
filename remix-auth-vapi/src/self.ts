/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright Oxide Computer Company
 */

import { vApiRequest } from './client'
import type { GetUserResponse } from './types'

/**
 * Fetch the authenticated user (`GET /self`) from a v-api based service.
 * `Permission` should be the consuming service's own permission string union.
 */
export async function getSelf<Permission extends string = string>(
    host: string,
    token: string,
): Promise<GetUserResponse<Permission>> {
    return vApiRequest<GetUserResponse<Permission>>(host, '/self', { method: 'GET', token })
}
