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

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

final class DefaultJwkHttpClientSupplier implements Supplier<HttpClient>
{

    private final CloseableHttpClient _httpClient = HttpClients
            .custom()
            .disableAuthCaching()
            .disableAutomaticRetries()
            .disableRedirectHandling()
            .setConnectionTimeToLive(2, TimeUnit.SECONDS)
            .build();

    @Override
    public HttpClient get()
    {
        return _httpClient;
    }
}
