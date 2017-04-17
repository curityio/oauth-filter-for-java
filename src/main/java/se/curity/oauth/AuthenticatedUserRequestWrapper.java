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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;

class AuthenticatedUserRequestWrapper extends HttpServletRequestWrapper
{
    /**
     * String identifier for OAuth authentication (i.e., authentication that conforms to RFC 6750). Value "OAUTH".
     *
     * @see <a href="https://tools.ietf.org/html/rfc6750">RFC 6750 - The OAuth 2.0 Authorization Framework: Bearer
     * Token Usage</a>
     */
    @SuppressWarnings("WeakerAccess")
    public static final String OAUTH_AUTH = "OAUTH";

    private final HttpServletRequest _request;

    private AuthenticatedUser _authenticatedUser; // Not final because logout mutates this

    AuthenticatedUserRequestWrapper(HttpServletRequest request, AuthenticatedUser authenticatedUser)
    {
        super(request);

        _request = request;
        _authenticatedUser = authenticatedUser;
    }

    @Override
    public String getRemoteUser()
    {
        return _authenticatedUser == null ? _request.getRemoteUser() : _authenticatedUser.getSubject();
    }

    @Override
    public Principal getUserPrincipal()
    {
        return _authenticatedUser == null ? _request.getUserPrincipal() : _authenticatedUser::getSubject;
    }

    @Override
    public String getAuthType()
    {
        //noinspection VariableNotUsedInsideIf
        return _authenticatedUser == null ? _request.getAuthType() : OAUTH_AUTH;
    }

    @Override
    public boolean authenticate(HttpServletResponse response) throws IOException, ServletException
    {
        return _authenticatedUser != null || (response.isCommitted() &&
                (response.getStatus() == HttpServletResponse.SC_UNAUTHORIZED ||
                        response.getStatus() == HttpServletResponse.SC_FORBIDDEN));
    }

    @Override
    public void login(String username, String password) throws ServletException
    {
        throw new ServletException("Authentication with username/password is not supported");
    }

    @Override
    public void logout() throws ServletException
    {
        _authenticatedUser = null;
    }
}
