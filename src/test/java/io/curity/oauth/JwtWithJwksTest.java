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
import org.mockito.Mock;

import javax.json.JsonObject;
import javax.json.JsonReaderFactory;
import javax.json.JsonString;
import javax.json.spi.JsonProvider;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class JwtWithJwksTest
{
    private static final Logger _logger = LogManager.getLogger(JwtWithJwksTest.class);

    private final String SUBJECT = "testsubject";
    private final String AUDIENCE = "foo:audience";
    private final String ISSUER = "test:issuer";
    private final int EXPIRATION = 200;
    private final String EXTRA_CLAIM = "TEST_KEY";
    private final String EXTRA_CLAIM_VALUE = "TEST_VALUE";

    // Used for signing tokens
    private final String PATH_TO_KEY = "/Se.Curity.Test.p12";
    private final String KEY_PWD = "Password1";

    private String _testToken;
    private KeyStore _keyStore;

    @Parameterized.Parameter()
    public String _keyAlias;

    @Parameterized.Parameter(1)
    public String _algorithm;

    @Parameterized.Parameter(2)
    public String _keyId;

    @Parameterized.Parameters
    public static Object[] keysToTest() {
        return new Object[][] { {"se.curity.test", "RS256", "-38074812"}, {"se.curity.test.ed25519", "EdDSA", "-1909572257"}, {"se.curity.test.ed448", "EdDSA", "1716999904"} };
    }

    @Before
    public void before() throws Exception
    {
        loadKeyStore();

        PrivateKey key = getPrivateKey();

        if (!_algorithm.equals("EdDSA")) {
            // Create test token on the fly
            JwtTokenIssuer issuer = new JwtTokenIssuer(ISSUER, _algorithm, key, _keyId);
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
    public void testFindAndValidateWithOneJwk() throws Exception
    {
        //JwtValidator validator = new JwtValidatorWithCert(ISSUER, AUDIENCE, prepareKeyMap());
        JsonReaderFactory jsonReaderFactory = JsonProvider.provider().createReaderFactory(Collections.emptyMap());
        WebKeysClient webKeysClient = mock(WebKeysClient.class);

        JwtValidatorWithJwk validator = new JwtValidatorWithJwk(0, webKeysClient, AUDIENCE, ISSUER,jsonReaderFactory);
        when(webKeysClient.getKeys()).thenReturn(prepareKeyMap().get(_keyId));
        _logger.info("test token = {}", _testToken);

        JsonData validatedToken = validator.validate(_testToken);

        assertNotNull(validatedToken);
    }

    @Test
    public void testValidContentInToken() throws Exception
    {
        //JwtValidator validator = new JwtValidatorWithCert(ISSUER, AUDIENCE, prepareKeyMap());
        JsonReaderFactory jsonReaderFactory = JsonProvider.provider().createReaderFactory(Collections.emptyMap());
        WebKeysClient webKeysClient = mock(WebKeysClient.class);

        JwtValidatorWithJwk validator = new JwtValidatorWithJwk(0, webKeysClient, AUDIENCE, ISSUER,jsonReaderFactory);
        when(webKeysClient.getKeys()).thenReturn(prepareKeyMap().get(_keyId));
        _logger.info("test token = {}", _testToken);

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
     * Load the private keymap with the kid and the jwks
     * The map only contains a single key
     * @return a map with a single entry representing a JWKS that contains the key with the keyid
     */
    private Map<String, String> prepareKeyMap()
    {
        Map<String, String> keys = new HashMap<>();

        keys.put("-38074812","{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"-38074812\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"yMAHZiIfbAgmZJ-_4Gj-wdS8rvaKNBbnHz_krmd-kkX51bA1EsUc0CN672-xnUb_-E_-u_GoWhJzdjiBuz9XasSfQK8WyAwbc7MLkw40A7Zxl2sfsxGTod3qi1u8mjguoc9CbVqPdYe_9YPVxoK4CeJz6V8AsPcxVJxYq6os1rI9qFx_6a1JdQEhetGtkHLFvwo80UTzKXKhGXSu96WrXnkDE8Kw5TSKvh2gI_BX4QHXjE82xldJRJ8QIXGpRNbdyzGkUdjsrhmZl3ARC9IUlxmowkcEEIzjfbOKBVGrVcJ7rHb0GYNaKtMB_MlH1uAPDxl6qKeXOAZ8YEZ1r0ToPw\",\"e\":\"AQAB\",\"x5t\":\"MR-pGTa866RdZLjN6Vwrfay907g\"}]}");
        keys.put("-1909572257", "{\"keys\":[{\"kty\":\"OKP\",\"kid\":\"-1909572257\",\"use\":\"sig\",\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"x\":\"XWxGtApfcqmKI7p0OKnF5JSEWMVoLsytFXLEP7xZ_l8\",\"x5t\":\"SHd4HCUdA8HJVGM2UWz5NmIPTG0\"}]}");
        keys.put("1716999904","{\"keys\":[{\"kty\":\"OKP\",\"kid\":\"1716999904\",\"use\":\"sig\",\"alg\":\"EdDSA\",\"crv\":\"Ed448\",\"x\":\"lDc565Rydl9MUCoOB9JpGV3pUSHm7FvuiuEMvrvRkS7PeYL41rPU6s2rMdLeHiXfSxvR1veh4C0A\",\"x5t\":\"1IRTBLLQeiL2YZLB1VDDvCTGozc\"}]}");
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
