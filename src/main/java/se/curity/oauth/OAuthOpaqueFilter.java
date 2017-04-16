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

import javax.json.JsonReaderFactory;
import javax.json.spi.JsonProvider;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import static se.curity.oauth.FilterHelper.getInitParamValue;
import static se.curity.oauth.FilterHelper.initParamsMapFrom;

public class OAuthOpaqueFilter extends OAuthFilter
{
    private static final Logger _logger = Logger.getLogger(OAuthOpaqueFilter.class.getName());

    private String _oauthHost = null;
    private String[] _scopes = null;
    private TokenValidator _opaqueTokenValidator = null;

    private interface InitParams
    {
        String SCOPE = "scope";
    }

    public void init(FilterConfig filterConfig) throws ServletException
    {
        Map<String, String> initParams = initParamsMapFrom(filterConfig);

        String scope = getInitParamValue(InitParams.SCOPE, initParams);

        _scopes = scope.split("\\s+");

        synchronized (this)
        {
            if (_opaqueTokenValidator == null)
            {
                _opaqueTokenValidator = createTokenValidator(initParams);

                _logger.info(() -> String.format("%s successfully initialized", OAuthFilter.class.getSimpleName()));
            }
            else
            {
                _logger.warning("Attempted to set introspect URI more than once! Ignoring further attempts.");
            }
        }
    }

    @Override
    protected String getOAuthServerRealm() throws UnavailableException
    {
        if (_oauthHost == null)
        {
            throw new UnavailableException("Filter not initialized");
        }

        return _oauthHost;
    }

    protected String[] getScopes() throws UnavailableException
    {
        return _scopes == null ? NO_SCOPES : _scopes;
    }

    @Override
    protected TokenValidator createTokenValidator(Map<String, ?> initParams) throws UnavailableException
    {
        // Like in the OAuthJwtFilter, we'll reuse the config of this filter + the service locator to
        // get a JsonReaderFactory
        JsonReaderFactory jsonReaderFactory = JsonProvider.provider().createReaderFactory(initParams);
        IntrospectionClient introspectionClient = HttpClientProvider.provider()
                .createIntrospectionClient(initParams);

        return new OpaqueTokenValidator(introspectionClient, jsonReaderFactory);
    }

    @Override
    protected Optional<AuthenticatedUser> authenticate(String token) throws ServletException
    {
        AuthenticatedUser result = null;

        try
        {
            Optional<? extends TokenData> validationResult = _opaqueTokenValidator.validate(token);

            if (validationResult.isPresent())
            {
                TokenData opaqueToken = validationResult.get();

                result = AuthenticatedUser.from(validationResult.get());
            }
        }
        catch (Exception e)
        {
            _logger.fine(() -> String.format("Failed to validate incoming token due to: %s", e.getMessage()));
        }

        return Optional.ofNullable(result);
    }

    @Override
    public void destroy()
    {
        _logger.info("Destroying OAuthFilter");

        if (_opaqueTokenValidator != null)
        {
            try
            {
                _opaqueTokenValidator.close();
            }
            catch (IOException e)
            {
                _logger.log(Level.WARNING, "Problem closing jwk client", e);
            }
        }
    }
}
