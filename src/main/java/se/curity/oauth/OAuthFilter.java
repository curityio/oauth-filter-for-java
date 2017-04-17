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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class OAuthFilter implements Filter
{
    private static final String[] NO_SCOPES = {};
    private static final Logger _logger = Logger.getLogger(OAuthFilter.class.getName());
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String AUTHORIZATION = "Authorization";

    private Map<String, String> _filterConfig; // Protected, so subclasses don't have to repeat the conversion to this
    private String _oauthHost = null;
    private String[] _scopes = null;

    private interface InitParams
    {
        String OAUTH_HOST = "oauthHost";
        String SCOPE = "scope";
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
        _filterConfig = FilterHelper.initParamsMapFrom(filterConfig);

        _oauthHost = FilterHelper.getInitParamValue(InitParams.OAUTH_HOST, _filterConfig);

        _scopes = FilterHelper.getOptionalInitParamValue(InitParams.SCOPE, _filterConfig, it -> it.split("\\s+"))
                .orElse(NO_SCOPES);
    }

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
        Optional<String> token = extractAccessTokenFromHeader(servletRequest);
        String oauthHost = getOAuthServerRealm();

        if (!token.isPresent())
        {
            setReAuthenticate401(response, oauthHost);

            return;
        }

        Optional<AuthenticatedUser> maybeAuthenticatedUser = authenticate(token.get());

        if (!maybeAuthenticatedUser.isPresent())
        {
            setReAuthenticate401(response, oauthHost);

            return;
        }

        AuthenticatedUser authenticatedUser = maybeAuthenticatedUser.get();

        if (!isAuthorized(authenticatedUser))
        {
            //403 Forbidden Scope header
            setForbidden403(response, oauthHost);

            return;
        }

        if (filterChain != null)
        {
            filterChain.doFilter(
                    new AuthenticatedUserRequestWrapper((HttpServletRequest)servletRequest, authenticatedUser),
                    servletResponse);
        }
    }

    protected Map<String, String> getFilterConfiguration()
    {
        return _filterConfig;
    }

    private void setReAuthenticate401(HttpServletResponse response, String oauthHost) throws IOException
    {
        String msg = String.format("Bearer realm=\"%s\"", oauthHost);

        response.setHeader(WWW_AUTHENTICATE, msg);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void setForbidden403(HttpServletResponse response, String oauthHost) throws IOException
    {
        String msg = String.format("Bearer realm=\"%s\"", oauthHost);

        response.setHeader(WWW_AUTHENTICATE, msg);
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }

    /**
     * Returns the realm of the OAuth server.
     *
     * <p>This is used when the filter returns 401, Access Denied, or 403, Forbiggen, with a WWW-Authenticate HTTP
     * indicating to the client that authentication is required</p>
     *
     * @return The OAuth server's realm as string
     */
    protected String getOAuthServerRealm() throws UnavailableException
    {
        if (_oauthHost == null)
        {
            throw new UnavailableException("Filter not initialized");
        }

        return _oauthHost;
    }

    protected abstract TokenValidator createTokenValidator(Map<String, ?> initParams) throws UnavailableException;

    protected abstract TokenValidator getTokenValidator();

    /**
     * This is the authenticate method of the filter, it will take the token as string input and
     * must perform the appropriate operation to validate the token.
     * @param token - The token extracted from the Authorization header and stripped of the Bearer
     * @return An AuthenticatedUser if the token was valid, or null if not.
     * @throws ServletException when authentication fails for some exceptional reason
     */
    protected Optional<AuthenticatedUser> authenticate(String token) throws ServletException
    {
        AuthenticatedUser result = null;

        try
        {
            TokenData validationResult = getTokenValidator().validate(token);

            result = AuthenticatedUser.from(validationResult);
        }
        catch (Exception e)
        {
            _logger.fine(() -> String.format("Failed to validate incoming token due to: %s", e.getMessage()));
        }

        return Optional.ofNullable(result);
    }
    /**
     * Authorizes the current request by checking that all configured scopes are included in the one presented in the
     * request.
     *
     * <p>If no scopes were configured for the filter, then any request is authorized. When a set of scopes are
     * configured, however, the filter will ensure that all such scopes are included in the presented token.</p>
     *
     * @param authenticatedUser the user that was authenticated
     * @return true if access is allowed
     */
    protected boolean isAuthorized(AuthenticatedUser authenticatedUser) throws ServletException
    {
        List<String> requiredScopes = Arrays.asList(_scopes);

        // No scopes required for authorization
        return requiredScopes.isEmpty() || authenticatedUser.getScopes().containsAll(requiredScopes);
    }

    @Override
    public void destroy()
    {
        _logger.info("Destroying OAuthFilter");

        if (getTokenValidator() != null)
        {
            try
            {
                getTokenValidator().close();
            }
            catch (IOException e)
            {
                _logger.log(Level.WARNING, "Problem closing token validator", e);
            }
        }
    }

    /**
     * Extracts the token from the Authorization header, removing the Bearer prefix
     * @param request The incoming request
     * @return the token or null if not present
     */
    private Optional<String> extractAccessTokenFromHeader(ServletRequest request)
    {
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        String authorizationHeader = httpRequest.getHeader(AUTHORIZATION);
        String result = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer"))
        {
            String[] tokenSplit = authorizationHeader.split("[Bb][Ee][Aa][Rr][Ee][Rr]\\s+");

            if(tokenSplit.length != 2)
            {
                _logger.fine("Incoming token in Authorization header is not a Bearer token");
            }
            else
            {
                result = tokenSplit[1];
            }
        }

        return Optional.ofNullable(result);
    }
}
