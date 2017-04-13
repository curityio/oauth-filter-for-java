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

package se.curity.examples.oauth;

import com.google.common.collect.ImmutableMultimap;
import com.google.common.io.Closeables;
import org.apache.http.client.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.examples.oauth.opaque.OpaqueToken;
import se.curity.examples.oauth.opaque.OpaqueTokenValidator;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static se.curity.examples.oauth.FilterHelper.getInitParamValue;
import static se.curity.examples.oauth.FilterHelper.initParamsMapFrom;

public class OAuthOpaqueFilter extends OAuthFilter
{
    private static final Logger _logger = LoggerFactory.getLogger(OAuthOpaqueFilter.class);

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
                    _logger.error("Invalid parameters", e);

                    throw new UnavailableException("Service is unavailable");
                }
                _logger.info("{} successfully initialized", OAuthFilter.class.getSimpleName());
            }
            else
            {
                _logger.warn("Attempted to set introspect URI more than once! Ignoring further attempts.");
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

    protected @Nonnull String[] getScopes() throws UnavailableException
    {
        if (_scopes == null)
        {
            throw new UnavailableException("Filter not initialized");
        }

        return _scopes;
    }

    @Nullable
    @Override
    protected AuthenticatedUser authenticate(String token) throws IOException, ServletException
    {
        @Nullable OpaqueToken opaqueToken = _opaqueTokenValidator.validate(token);

        if (opaqueToken == null)
        {
            return null;
        }

        return new AuthenticatedUser(opaqueToken.getSubject(), opaqueToken.getScope());
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
            _logger.warn("Problem closing jwk client", e);
        }
    }
}
