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

package io.curity.oauth;

import jakarta.servlet.UnavailableException;

import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * Service Provider Interface (SPI) for creating HTTP clients used by the filter.
 * <p>
 * Implementations are discovered via {@link ServiceLoader}. The first provider
 * found for this SPI is used; if none is available, {@link DefaultHttpClientProvider}
 * is used as a fallback, which requires the Apache HTTP Client library.
 */
public abstract class HttpClientProvider
{
    public HttpClientProvider()
    {
    }

    /**
     * Resolve the active {@link HttpClientProvider} implementation.
     *
     * @return the provider discovered through the SPI, or the default provider when none is registered
     */
    static HttpClientProvider provider()
    {
        ServiceLoader<HttpClientProvider> loader = ServiceLoader.load(HttpClientProvider.class);
        Iterator<HttpClientProvider> it = loader.iterator();

        if (it.hasNext())
        {
            return it.next();
        }

        return new DefaultHttpClientProvider();
    }

    /**
     * Create an introspection client using the supplied configuration.
     *
     * @param config filter configuration values
     * @return a client capable of token introspection
     * @throws UnavailableException if the client cannot be created
     */
    public abstract IntrospectionClient createIntrospectionClient(Map<String, ?> config) throws UnavailableException;

    /**
     * Create a web keys client using the supplied configuration.
     *
     * @param config filter configuration values
     * @return a client capable of retrieving web keys
     * @throws UnavailableException if the client cannot be created
     */
    public abstract WebKeysClient createWebKeysClient(Map<String, ?> config) throws UnavailableException;
}
