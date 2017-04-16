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

import javax.servlet.UnavailableException;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;

public abstract class HttpClientProvider
{
    HttpClientProvider()
    {
    }

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

    public abstract IntrospectionClient createIntrospectionClient(Map<String, ?> config) throws UnavailableException;

    public abstract WebKeysClient createWebKeysClient(Map<String, ?> config) throws UnavailableException;
}
