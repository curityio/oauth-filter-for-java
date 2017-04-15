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

import se.curity.oauth.jwt.JwtValidatorWithJwk;

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

public class OAuthJwtFilter extends OAuthFilter
{
    private static final Logger _logger = Logger.getLogger(OAuthJwtFilter.class.getName());

    private String _oauthHost = null;
    private String[] _scopes = null;
    private long _minKidReloadTimeInSeconds = 3600;

    private TokenValidator _jwtValidator = null;

    private interface InitParams
    {
        String OAUTH_HOST = "oauthHost";
        String OAUTH_PORT = "oauthPort";
        String SCOPE = "scope";
        String MIN_KID_RELOAD_TIME = "_minKidReloadTimeInSeconds";
    }

    public void init(FilterConfig filterConfig) throws ServletException
    {
        Map<String, String> initParams = FilterHelper.initParamsMapFrom(filterConfig);

        _oauthHost = FilterHelper.getInitParamValue(InitParams.OAUTH_HOST, initParams);

        String scope = FilterHelper.getInitParamValue(InitParams.SCOPE, initParams);
        _scopes = scope.split("\\s+");

        Optional<Long> minKidReloadTime = FilterHelper.getOptionalInitParamValue(
                InitParams.MIN_KID_RELOAD_TIME,
                initParams, Long::parseLong);
        _minKidReloadTimeInSeconds = minKidReloadTime.orElse(_minKidReloadTimeInSeconds);

        synchronized (this)
        {
            if (_jwtValidator == null)
            {
                _jwtValidator = createTokenValidator(initParams);
                
                _logger.info(() -> String.format("%s successfully initialized", OAuthFilter.class.getSimpleName()));
            }
            else
            {
                _logger.warning("Attempted to set webkey URI more than once! Ignoring further attempts.");
            }
        }
    }

    @Override
    protected String getOAuthServerRealm()
    {
        if (_oauthHost == null)
        {
            throw new IllegalStateException("Filter not initialized");
        }
        
        return _oauthHost;
    }

    @Override
    protected String[] getScopes() throws UnavailableException
    {
        return _scopes == null ? NO_SCOPES : _scopes;
    }

    @Override
    protected TokenValidator createTokenValidator(Map<String, ?> initParams) throws UnavailableException
    {
        // Pass all of the filter's config to the ReaderFactory factory method. It'll ignore anything it doesn't
        // understand (per JSR 353). This way, clients can change the provider using the service locator and configure
        // the ReaderFactory using the filter's config.
        JsonReaderFactory jsonReaderFactory = JsonProvider.provider().createReaderFactory(initParams);
        WebKeysClient webKeysClient = HttpClientProvider.provider().createWebKeysClient(initParams);

        return _jwtValidator = new JwtValidatorWithJwk(_minKidReloadTimeInSeconds, webKeysClient, jsonReaderFactory);
    }

    @Override
    protected Optional<AuthenticatedUser> authenticate(String token) throws IOException, ServletException
    {
        AuthenticatedUser result = null;

        try
        {
            Optional<? extends TokenData> validationResult = _jwtValidator.validate(token);

            if (validationResult.isPresent())
            {
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

        if (_jwtValidator != null)
        {
            try
            {
                _jwtValidator.close();
            }
            catch (IOException e)
            {
                _logger.log(Level.WARNING, "Problem closing jwk client", e);
            }
        }
    }
}
