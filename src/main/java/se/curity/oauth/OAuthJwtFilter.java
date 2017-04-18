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
import java.util.Map;
import java.util.logging.Logger;

public class OAuthJwtFilter extends OAuthFilter
{
    private static final Logger _logger = Logger.getLogger(OAuthJwtFilter.class.getName());

    private long _minKidReloadTimeInSeconds = 3600;

    private TokenValidator _jwtValidator = null;

    private interface InitParams
    {
        String ISSUER = "issuer";
        String AUDIENCE = "audience";
        String MIN_KID_RELOAD_TIME = "_minKidReloadTimeInSeconds";
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
        super.init(filterConfig);

        _minKidReloadTimeInSeconds = FilterHelper.getOptionalInitParamValue(
                InitParams.MIN_KID_RELOAD_TIME,
                getFilterConfiguration(), Long::parseLong).orElse(_minKidReloadTimeInSeconds);

        synchronized (this)
        {
            if (_jwtValidator == null)
            {
                _jwtValidator = createTokenValidator(getFilterConfiguration());
                
                _logger.info(() -> String.format("%s successfully initialized", OAuthFilter.class.getSimpleName()));
            }
            else
            {
                _logger.warning("Attempted to set webkey URI more than once! Ignoring further attempts.");
            }
        }
    }

    @Override
    protected TokenValidator createTokenValidator(Map<String, ?> filterConfig) throws UnavailableException
    {
        // Pass all of the filter's config to the ReaderFactory factory method. It'll ignore anything it doesn't
        // understand (per JSR 353). This way, clients can change the provider using the service locator and configure
        // the ReaderFactory using the filter's config.
        JsonReaderFactory jsonReaderFactory = JsonProvider.provider().createReaderFactory(filterConfig);
        WebKeysClient webKeysClient = HttpClientProvider.provider().createWebKeysClient(filterConfig);
        String audience = FilterHelper.getInitParamValue(InitParams.AUDIENCE, filterConfig);
        String issuer = FilterHelper.getInitParamValue(InitParams.ISSUER, filterConfig);

        return _jwtValidator = new JwtValidatorWithJwk(_minKidReloadTimeInSeconds, webKeysClient, audience, issuer,
                jsonReaderFactory);
    }

    @Override
    protected TokenValidator getTokenValidator()
    {
        return _jwtValidator;
    }
}
