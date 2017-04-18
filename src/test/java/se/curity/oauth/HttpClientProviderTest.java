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

import org.junit.Test;

import javax.servlet.UnavailableException;
import java.util.Map;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

public class HttpClientProviderTest
{
    @Test
    public void provider() throws Exception
    {
        // GIVEN: The fake, test provider is wired up using the test resource file in META-INF/services

        // WHEN: the provider is fetched
        HttpClientProvider httpClientProvider = HttpClientProvider.provider();

        // THEN: the one that the ServiceLoader returns is the expected type
        assertThat(httpClientProvider, instanceOf(FakeHttpClientProvider.class));
    }

    public static class FakeHttpClientProvider extends HttpClientProvider
    {
        @Override
        public IntrospectionClient createIntrospectionClient(Map<String, ?> config) throws UnavailableException
        {
            return null;
        }

        @Override
        public WebKeysClient createWebKeysClient(Map<String, ?> config) throws UnavailableException
        {
            return null;
        }
    }
}