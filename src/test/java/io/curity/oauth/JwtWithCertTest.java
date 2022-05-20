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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.json.JsonObject;
import javax.json.JsonString;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.EdECPrivateKey;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;

@RunWith(Parameterized.class)
public class JwtWithCertTest
{
    private static final Logger _logger = LogManager.getLogger(JwtWithCertTest.class);

    private final String SUBJECT = "testsubject";
    private final String AUDIENCE = "foo:audience";
    private final String ISSUER = "test:issuer";
    private final int EXPIRATION = 200;
    private final String EXTRA_CLAIM = "TEST_KEY";
    private final String EXTRA_CLAIM_VALUE = "TEST_VALUE";

    private final String PATH_TO_KEY = "/Se.Curity.Test.p12";
    private final String KEY_PWD = "Password1";
    
    private String _testToken;
    private KeyStore _keyStore;

    @Parameterized.Parameter()
    public String _keyAlias;

    @Parameterized.Parameter(1)
    public String _algorithm;

    @Parameterized.Parameters
    public static Object[] keysToTest() {
        return new Object[][] { {"se.curity.test", "RS256"}, {"se.curity.test.ed25519", "EdDSA"}, {"se.curity.test.ed448", "EdDSA"} };
    }

    @Before
    public void before() throws Exception
    {
        loadKeyStore();

        PrivateKey key = getPrivateKey();
        Certificate cert = getCertificate();

        if (!_algorithm.equals("EdDSA")) {
            // Create test token on the fly
            JwtTokenIssuer issuer = new JwtTokenIssuer(ISSUER, _algorithm, key, cert);
            Map<String, Object> attributes = new HashMap<>();
            attributes.put(EXTRA_CLAIM, EXTRA_CLAIM_VALUE);
            _testToken = issuer.issueToken(SUBJECT, AUDIENCE, EXPIRATION, attributes);
        } else {
            // Use hardcoded values until jose4j supports EdDSA
            String curveName = ((EdECPrivateKey) key).getParams().getName();
            if ("Ed25519".equals(curveName)) {
                _testToken ="eyJraWQiOiItMTkwOTU3MjI1NyIsIng1dCI6IlNIZDRIQ1VkQThISlZHTTJVV3o1Tm1JUFRHMCIsIng1dCNTMjU2IjoiS0lZVnBHXzVXSnh0ZUdOUTVLR043M0xlQWNHS0w4MmMyWFhaR0M5RUNKVSIsImFsZyI6IkVkRFNBIn0.eyJqdGkiOiJlMzE2YjBmOS1mN2JlLTQ3M2QtOGMzNi05NGMwNzRlMjMzNjEiLCJkZWxlZ2F0aW9uSWQiOiIzZDE2NzM5Ni02NGEzLTQ2MmYtOGMyZS02MzdhYzM0NzdkMTMiLCJleHAiOjE5Njg0MDkwNzMsIm5iZiI6MTY1MzA0OTA3Mywic2NvcGUiOiJyZWFkIG9wZW5pZCIsImlzcyI6InRlc3Q6aXNzdWVyIiwic3ViIjoidGVzdHN1YmplY3QiLCJhdWQiOiJmb286YXVkaWVuY2UiLCJpYXQiOjE2NTMwNDkwNzMsInB1cnBvc2UiOiJhY2Nlc3NfdG9rZW4iLCJURVNUX0tFWSI6IlRFU1RfVkFMVUUifQ.NGWCDwzCPOx50-WBJRqKFvPy2562rqFjNS3Q9zmJqNhdxtZK3s7g7JWtgI_AwnJBnaPeC1ATMYyxKjionwzQAA";
            } else {
                _testToken ="eyJraWQiOiIxNzE2OTk5OTA0IiwieDV0IjoiMUlSVEJMTFFlaUwyWVpMQjFWRER2Q1RHb3pjIiwieDV0I1MyNTYiOiJTbGVDbTlwRVI5a2ZiTjBYeGlqa1g4MmdyR0hUYXhOTkNCRHNUMHR1M3lBIiwiYWxnIjoiRWREU0EifQ.eyJqdGkiOiIyNjNiNmM2OS02NTExLTQ5YjktYWVlYi0yY2JkOGMyMGE3NGUiLCJkZWxlZ2F0aW9uSWQiOiIwY2NjZmMyZi1mY2EzLTRlOGQtOTgxYy05ZjU5MzIyNmYyNTEiLCJleHAiOjE5Njg0MDg5NzUsIm5iZiI6MTY1MzA0ODk3NSwic2NvcGUiOiJyZWFkIG9wZW5pZCIsImlzcyI6InRlc3Q6aXNzdWVyIiwic3ViIjoidGVzdHN1YmplY3QiLCJhdWQiOiJmb286YXVkaWVuY2UiLCJpYXQiOjE2NTMwNDg5NzUsInB1cnBvc2UiOiJhY2Nlc3NfdG9rZW4iLCJURVNUX0tFWSI6IlRFU1RfVkFMVUUifQ.2gcRnLTFnCsdkElgcecSjxvrKA3bKAFuUf5vhVapdLqxZvx6E1BblTzjaVjqy3OT0OzdN3p1q5kApJ5EjVUT0tdjHVxZMBtkosviYM5EL2UkJO_T3tA-on7h0lfcufxnhd_TUOlM_YTkJxFGSkOtLg4A";
            }
        }
    }

    @Test
    public void testFindAndValidateWithOneCert() throws Exception
    {
        JwtValidator validator = new JwtValidatorWithCert(ISSUER, AUDIENCE, prepareKeyMap());

        _logger.info("test token = {}", _testToken);

        JsonData validatedToken = validator.validate(_testToken);

        assertNotNull(validatedToken);
    }

    @Test
    public void testValidContentInToken() throws Exception
    {
        JwtValidator validator = new JwtValidatorWithCert(ISSUER, AUDIENCE, prepareKeyMap());

        JsonData result = validator.validate(_testToken);

        _logger.info("test token = {}", _testToken);

        assertNotNull(result);

        JsonObject jsonObject = result.getJsonObject();

        assertTrue(jsonObject.containsKey("sub"));
        assertTrue(jsonObject.containsKey(EXTRA_CLAIM));

        assertEquals(SUBJECT, ((JsonString) jsonObject.get("sub")).getString());
        assertEquals(EXTRA_CLAIM_VALUE, ((JsonString) jsonObject.get(EXTRA_CLAIM)).getString());
    }

    /**
     * Load the private Keymap with the x5t256 thumbprint and the public key
     * The map only contains a single key
     * @return a map with a single entry of a certificate thumbprint and the corresponding public key
     * @throws Exception When key could not be loaded from certificate
     */
    private Map<String, PublicKey> prepareKeyMap() throws Exception
    {
        Map<String, PublicKey> keys = new HashMap<>();

        Certificate cert = getCertificate();

        PublicKey key = cert.getPublicKey();

        byte[] x5tS256 = DigestUtils.sha256(cert.getEncoded());
        String b64x5tS256 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(x5tS256);

        keys.put(b64x5tS256, key);

        return keys;
    }

    private void loadKeyStore()
            throws Exception
    {
        URL url = getClass().getResource(PATH_TO_KEY);
        assert url != null;
        File certFile = new File(url.getFile());

        InputStream keyIS = new FileInputStream(certFile);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyIS, KEY_PWD.toCharArray());

        keyIS.close();

        this._keyStore=keyStore;
    }

    private PrivateKey getPrivateKey()
            throws Exception
    {
        return (PrivateKey)this._keyStore.getKey(_keyAlias, KEY_PWD.toCharArray());

    }

    private Certificate getCertificate() throws KeyStoreException {
        //Get key by alias (found in the p12 file using:
        //keytool -list -keystore test-root-ca.p12 -storepass foobar -storetype PKCS12
        return this._keyStore.getCertificate(_keyAlias);
    }
}
