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

package io.curity.oauth;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

final class TestKeyStoreHelper
{
    private static final String PATH_TO_KEY = "/Se.Curity.Test.p12";
    private static final String KEY_PWD = "Password1";

    private TestKeyStoreHelper()
    {
    }

    static KeyStore loadKeyStore() throws Exception
    {
        return loadKeyStore(TestKeyStoreHelper.class, PATH_TO_KEY);
    }

    static KeyStore loadKeyStore(Class<?> testClass, String keyPath) throws Exception
    {
        URL url = testClass.getResource(keyPath);
        assert url != null;
        File certFile = new File(url.getFile());

        try (InputStream keyIS = new FileInputStream(certFile))
        {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(keyIS, KEY_PWD.toCharArray());
            return keyStore;
        }
    }

    static PrivateKey getPrivateKey(KeyStore keyStore, String keyAlias) throws Exception
    {
        return (PrivateKey) keyStore.getKey(keyAlias, KEY_PWD.toCharArray());
    }

    static Certificate getCertificate(KeyStore keyStore, String keyAlias) throws Exception
    {
        return keyStore.getCertificate(keyAlias);
    }
}
