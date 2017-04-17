/*
 * Copyright (C) 2017 Curity AB.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.curity.oauth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;

class AuthenticatedUserRequestWrapper extends HttpServletRequestWrapper
{
    private final AuthenticatedUser _authenticatedUser;
    private final HttpServletRequest _request;

    AuthenticatedUserRequestWrapper(HttpServletRequest request, AuthenticatedUser authenticatedUser)
    {
        super(request);

        _request = request;
        _authenticatedUser = authenticatedUser;
    }

    @Override
    public String getRemoteUser()
    {
        return _authenticatedUser == null ? _request.getRemoteUser() :  _authenticatedUser.getSubject();
    }

    @Override
    public Principal getUserPrincipal()
    {
        return _authenticatedUser == null ? _request.getUserPrincipal() : _authenticatedUser::getSubject;
    }
}
