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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Properties;
import java.util.function.Supplier;

final class ExternalResourceLoader
{
    private static final Logger _logger = LoggerFactory.getLogger(ExternalResourceLoader.class);

    private static final String PROPS_FILE_NAME = "OAuthFilter.properties";
    private static final String PROPERTIES_LOCATION = "/META-INF/services/" + PROPS_FILE_NAME;
    private static final String HTTP_CLIENT_PROPERTY = "openid.httpClientSupplier.className";

    private static ExternalResourceLoader instance;

    private final Properties _properties;

    static synchronized ExternalResourceLoader getInstance()
    {
        if (instance == null)
        {
            instance = new ExternalResourceLoader();
        }

        return instance;
    }

    private ExternalResourceLoader()
    {
        _properties = new Properties(defaultProperties());

        InputStream stream = getClass().getResourceAsStream(PROPERTIES_LOCATION);

        if (stream == null)
        {
            try
            {
                stream = new BufferedInputStream(new FileInputStream(PROPS_FILE_NAME));

                _logger.info("Found properties file in the working directory");
            }
            catch (FileNotFoundException ignored)
            {
                // not a problem
            }
        }
        if (stream == null)
        {
            _logger.info("No external config found, using defaults");
        }
        else
        {
            try (InputStream input = stream)
            {
                _properties.load(input);
            }
            catch (IOException e)
            {
                _logger.warn("Problem loading properties at " + PROPERTIES_LOCATION, e);
            }
        }
    }

    private static Properties defaultProperties()
    {
        Properties properties = new Properties();

        properties.put(HTTP_CLIENT_PROPERTY, DefaultJwkHttpClientSupplier.class.getName());

        return properties;
    }

    HttpClient loadJwkHttpClient()
    {
        String httpClientSupplierClassName = _properties.getProperty(HTTP_CLIENT_PROPERTY);

        try
        {
            Class<? extends Supplier> supplierType = Class.forName(httpClientSupplierClassName)
                    .asSubclass(Supplier.class);

            _logger.info("Using HttpClientSupplier of type {}", supplierType.getName());

            Supplier<?> supplier = supplierType.newInstance();
            Object httpClient = supplier.get();

            return HttpClient.class.cast(httpClient);
        }
        catch (Exception e)
        {
            _logger.warn("Unable to load httpClientSupplier from " + PROPERTIES_LOCATION +
                    "\nWill fallback to the default HTTP Client", e);

            return new DefaultJwkHttpClientSupplier().get();
        }
    }
}
