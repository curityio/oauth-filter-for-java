/*
 * Copyright (C) 2016 Curity AB.
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

import com.google.common.collect.Sets;
import com.google.common.net.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public abstract class OAuthFilter implements Filter
{
    private static final Logger _logger = LoggerFactory.getLogger(OAuthFilter.class);

    public static final String PRINCIPAL = "principal";
    private static final String[] NO_PRESENTED_SCOPES = new String[0];

    @Override
    public abstract void init(FilterConfig filterConfig) throws ServletException;

    /**
     * The doFilter is the primary filter method of a Servlet filter. It is implemented as a final method
     * and will call the configured filters authenticate and authorize methods.
     * Authorize is optional to implement as this filter implements a default scope check method.
     * @param servletRequest The default servlet request
     * @param servletResponse The default servlet response
     * @param filterChain A filter chain to continue with after this filter is done
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public final void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException
    {
        HttpServletResponse response = (HttpServletResponse)servletResponse;
        @Nullable String token = extractAccessTokenFromHeader(servletRequest);
        String oauthHost = getOAuthHost();

        if (token == null)
        {
            setReAuthenticate401(response, oauthHost);

            return;
        }

        @Nullable AuthenticatedUser authenticatedUser = authenticate(token);

        if (authenticatedUser == null)
        {
            setReAuthenticate401(response, oauthHost);

            return;
        }

        if (!authorize(authenticatedUser.getScope()))
        {
            //403 Forbidden Scope header
            setForbidden403(response, oauthHost);

            return;
        }

        servletRequest.setAttribute(PRINCIPAL, authenticatedUser);

        if (filterChain != null)
        {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    private void setReAuthenticate401(HttpServletResponse response, String oauthHost) throws IOException
    {
        String msg = String.format("Bearer realm=\"%s\"", oauthHost);

        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, msg);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void setForbidden403(HttpServletResponse response, String oauthHost) throws IOException
    {
        String msg = String.format("Bearer realm=\"%s\"", oauthHost);

        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, msg);
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }

    /**
     * Returns the hostname of the OAuth server. This is used when the filter returns
     * 401 WWW-Authenticate to indicate the Token Realm
     * @return The OAuth hostname as string
     */
    protected abstract String getOAuthHost() throws ServletException;

    /**
     * Returns the configured scopes that are required to be present in a token for the
     * request to be authorized.
     * @return An array of required scopes, or an empty array if all scopes are allowed
     */
    protected abstract @Nonnull String[] getScopes() throws ServletException;

    /**
     * This is the authenticate method of the filter, it will take the token as string input and
     * must perform the appropriate operation to validate the token.
     * @param token - The token extracted from the Authorization header and stripped of the Bearer
     * @return An AuthenticatedUser if the token was valid, or null if not.
     * @throws IOException
     * @throws ServletException
     */
    protected abstract @Nullable AuthenticatedUser authenticate(String token) throws IOException, ServletException;

    /**
     * Authorizes the current request based on the scopes in the token against the scopes defined
     * in the filter. If the filter has no scopes defined, all scopes are allowed.
     * The filter will ensure that the union of all scopes required are available in the token.
     * @param scopesInToken the string of scopes presented in the token
     * @return true if access is allowed
     */
    protected boolean authorize(@Nullable String scopesInToken) throws ServletException
    {
        List<String> requiredScopes = Arrays.asList(getScopes());

        if (requiredScopes.size() == 0)
        {
            //No scopes required for authorization
            return true;
        }

        String[] presentedScopes = scopesInToken == null ? NO_PRESENTED_SCOPES : scopesInToken.split("\\s+");
        Set<String> presentedScopesList = Sets.newHashSet(presentedScopes);

        return presentedScopesList.containsAll(requiredScopes);
    }

    /**
     * Extracts the token from the Authorization header, removing the Bearer prefix
     * @param request The incoming request
     * @return the token or null if not present
     */
    private @Nullable String extractAccessTokenFromHeader(ServletRequest request)
    {
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        @Nullable String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer"))
        {
            String[] tokenSplit = authorizationHeader.split("[Bb][Ee][Aa][Rr][Ee][Rr]\\s+");

            if(tokenSplit.length != 2)
            {
                _logger.debug("Incoming token in Authorization header is not a Bearer token");
                return null;
            }

            return tokenSplit[1];
        }

        return null;
    }
}
