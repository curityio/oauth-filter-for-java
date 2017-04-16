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

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.servlet.UnavailableException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static se.curity.oauth.FilterHelper.getInitParamValue;

class DefaultHttpClientProvider extends HttpClientProvider
{
    private static final Logger _logger = Logger.getLogger(OAuthOpaqueFilter.class.getName());

    private interface InitParams
    {
        String OAUTH_HOST = "oauthHost";
        String OAUTH_PORT = "oauthPort";
        String JSON_WEB_KEYS_PATH = "jsonWebKeysPath";
        String INTROSPECTION_PATH = "introspectionPath";
        String CLIENT_ID = "clientId";
        String CLIENT_SECRET = "clientSecret";
    }

    @Override
    public IntrospectionClient createIntrospectionClient(Map<String, ?> config) throws UnavailableException
    {
        String oauthHost = getInitParamValue(InitParams.OAUTH_HOST, config);
        int oauthPort = getInitParamValue(InitParams.OAUTH_PORT, config, Integer::parseInt);

        String introspectionPath = getInitParamValue(InitParams.INTROSPECTION_PATH, config);
        String clientId = getInitParamValue(InitParams.CLIENT_ID, config);
        String clientSecret = getInitParamValue(InitParams.CLIENT_SECRET, config);

        URI introspectionUri = null;
        try
        {
            introspectionUri = new URI("https", null, oauthHost, oauthPort, introspectionPath, null, null);
        }
        catch (URISyntaxException e)
        {
            _logger.log(Level.SEVERE, "Invalid parameters", e);

            throw new UnavailableException("Service is unavailable");
        }

        HttpClient httpClient = HttpClients
                .custom()
                .disableAuthCaching()
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .setConnectionTimeToLive(2, TimeUnit.SECONDS)
                .build();

        return new DefaultIntrospectClient(introspectionUri, clientId, clientSecret, httpClient);
    }

    @Override
    public WebKeysClient createWebKeysClient(Map<String, ?> config) throws UnavailableException
    {
        URI webKeysUri;

        try
        {
            int oauthPort = FilterHelper.getInitParamValue(InitParams.OAUTH_PORT, config, Integer::parseInt);
            String webKeysPath = FilterHelper.getInitParamValue(InitParams.JSON_WEB_KEYS_PATH, config);
            String oauthHost = FilterHelper.getInitParamValue(InitParams.OAUTH_HOST, config);

            webKeysUri = new URI("https", null, oauthHost, oauthPort, webKeysPath, null, null);
        }
        catch (URISyntaxException e)
        {
            _logger.log(Level.SEVERE, "Invalid parameters", e);

            throw new UnavailableException("Service is unavailable");
        }

        HttpClient httpClient = HttpClients
                .custom()
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .setConnectionTimeToLive(2, TimeUnit.SECONDS)
                .build();

        return new DefaultWebKeysClient(webKeysUri, httpClient);
    }
}
