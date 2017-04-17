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

public class OAuthOpaqueFilter extends OAuthFilter
{
    private static final Logger _logger = Logger.getLogger(OAuthOpaqueFilter.class.getName());

    private TokenValidator _opaqueTokenValidator = null;

    private interface InitParams
    {
        String SCOPE = "scope";
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
        super.init(filterConfig);

        synchronized (this)
        {
            if (_opaqueTokenValidator == null)
            {
                _opaqueTokenValidator = createTokenValidator(getFilterConfiguration());

                _logger.info(() -> String.format("%s successfully initialized", OAuthFilter.class.getSimpleName()));
            }
            else
            {
                _logger.warning("Attempted to set introspect URI more than once! Ignoring further attempts.");
            }
        }
    }

    @Override
    protected TokenValidator getTokenValidator()
    {
        return _opaqueTokenValidator;
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
}
