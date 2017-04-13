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

import com.google.common.collect.ImmutableMultimap;
import com.google.common.io.Closeables;
import org.apache.http.client.HttpClient;
import se.curity.oauth.opaque.OpaqueToken;
import se.curity.oauth.opaque.OpaqueTokenValidator;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import static se.curity.oauth.FilterHelper.getInitParamValue;
import static se.curity.oauth.FilterHelper.initParamsMapFrom;

public class OAuthOpaqueFilter extends OAuthFilter
{
    private static final Logger _logger = Logger.getLogger(OAuthOpaqueFilter.class.getName());

    private final HttpClient _httpClient = ExternalResourceLoader.getInstance().loadJwkHttpClient();

    private String _oauthHost = null;
    private String[] _scopes = null;
    private OpaqueTokenValidator _opaqueTokenValidator = null;

    private interface InitParams
    {
        String OAUTH_HOST = "oauthHost";
        String OAUTH_PORT = "oauthPort";

        String INTROSPECTION_PATH = "introspectionPath";
        String CLIENT_ID = "clientId";
        String CLIENT_SECRET = "clientSecret";
        String SCOPE = "scope";
    }

    public void init(FilterConfig filterConfig) throws ServletException
    {
        ImmutableMultimap<String, String> initParams = initParamsMapFrom(filterConfig);

        _oauthHost = getInitParamValue(InitParams.OAUTH_HOST, initParams);
        int oauthPort = getInitParamValue(InitParams.OAUTH_PORT, initParams, Integer::parseInt);

        String introspectionPath = getInitParamValue(InitParams.INTROSPECTION_PATH, initParams);
        String clientId = getInitParamValue(InitParams.CLIENT_ID, initParams);
        String clientSecret = getInitParamValue(InitParams.CLIENT_SECRET, initParams);

        String scope = getInitParamValue(InitParams.SCOPE, initParams);
        _scopes = scope.split("\\s+");

        synchronized (this)
        {
            if (_opaqueTokenValidator == null)
            {
                try
                {
                    URI introspectionUri = new URI("https", null, _oauthHost, oauthPort, introspectionPath, null, null);
                    _opaqueTokenValidator = new OpaqueTokenValidator(introspectionUri, clientId, clientSecret, _httpClient);

                }
                catch (URISyntaxException e)
                {
                    _logger.log(Level.SEVERE, "Invalid parameters", e);

                    throw new UnavailableException("Service is unavailable");
                }
                _logger.info(() -> String.format("%s successfully initialized", OAuthFilter.class.getSimpleName()));
            }
            else
            {
                _logger.warning("Attempted to set introspect URI more than once! Ignoring further attempts.");
            }
        }
    }

    @Override
    protected String getOAuthHost() throws UnavailableException
    {
        if (_oauthHost == null)
        {
            throw new UnavailableException("Filter not initialized");
        }

        return _oauthHost;
    }

    protected String[] getScopes() throws UnavailableException
    {
        if (_scopes == null)
        {
            throw new UnavailableException("Filter not initialized");
        }

        return _scopes;
    }

    @Override
    protected Optional<AuthenticatedUser> authenticate(String token) throws IOException, ServletException
    {
        Optional<OpaqueToken> maybeOpaqueToken = _opaqueTokenValidator.validate(token);
        AuthenticatedUser result = null;

        if (maybeOpaqueToken.isPresent())
        {
            OpaqueToken opaqueToken = maybeOpaqueToken.get();
            
            result = new AuthenticatedUser(opaqueToken.getSubject(), opaqueToken.getScope());
        }

        return Optional.ofNullable(result);
    }

    @Override
    public void destroy()
    {
        try
        {
            Closeables.close(_opaqueTokenValidator, true);
        }
        catch (IOException e)
        {
            _logger.log(Level.WARNING, "Problem closing jwk client", e);
        }
    }
}
