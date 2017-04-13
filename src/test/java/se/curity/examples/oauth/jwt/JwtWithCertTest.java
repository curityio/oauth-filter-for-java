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

package se.curity.examples.oauth.jwt;

import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;

public class JwtWithCertTest
{
    private final String SUBJECT = "testsubject";
    private final String AUDIENCE = "foo:audience";
    private final String ISSUER = "test:issuer";
    private final int EXPIRATION = 200;
    private final String EXTRA_CLAIM = "TEST_KEY";
    private final String EXTRA_CLAIM_VALUE = "TEST_VALUE";

    private final String PATH_TO_KEY = "/Se.Curity.Test.p12";
    private final String KEY_ALIAS = "se.curity.test";
    private final String KEY_PWD = "Password1";


    private String _testToken;
    private KeyStore _keyStore;


    @Before
    public void before() throws Exception
    {

        loadKeyStore();

        PrivateKey key = getPrivateKey();
        Certificate cert = getCertificate();

        JwtTokenIssuer issuer = new JwtTokenIssuer(ISSUER, key, cert);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(EXTRA_CLAIM, EXTRA_CLAIM_VALUE);

        _testToken = issuer.issueToken(SUBJECT,AUDIENCE,EXPIRATION,attributes);
    }


    @Test
    public void testFindAndValidateWithOneCert() throws Exception
    {

        JwtValidator validator = new JwtValidatorWithCert(prepareKeyMap());
        assertNotNull(validator.validate(_testToken));

    }

    @Test
    public void testValidContentInToken() throws Exception
    {
        JwtValidator validator = new JwtValidatorWithCert(prepareKeyMap());

        Optional<Map<String, Object>> result = validator.validateAll(_testToken, AUDIENCE, ISSUER);

        assertTrue(result.isPresent());
        assertTrue(result.get().containsKey("sub"));
        assertTrue(result.get().containsKey(EXTRA_CLAIM));

        assertEquals(result.get().get("sub"), SUBJECT);
        assertEquals(result.get().get(EXTRA_CLAIM), EXTRA_CLAIM_VALUE);
    }

    /**
     * Load the private Keymap with the x5t256 thumbprint and the public key
     * The map only contains a single key
     * @return
     * @throws Exception
     */
    private Map<String, RSAPublicKey> prepareKeyMap() throws Exception
    {
        Map<String, RSAPublicKey> keys = new HashMap<>();

        Certificate cert = getCertificate();

        RSAPublicKey key = (RSAPublicKey)cert.getPublicKey();

        byte[] x5tS256 = DigestUtils.sha256(cert.getEncoded());
        String b64x5tS256 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(x5tS256);

        keys.put(b64x5tS256, key);

        return keys;
    }



    private void loadKeyStore()
            throws Exception
    {
        URL url = getClass().getResource(PATH_TO_KEY);
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
        return (PrivateKey)this._keyStore.getKey(KEY_ALIAS, KEY_PWD.toCharArray());

    }

    private Certificate getCertificate() throws Exception {
        //Get key by alias (found in the p12 file using:
        //keytool -list -keystore test-root-ca.p12 -storepass foobar -storetype PKCS12
        return (Certificate)this._keyStore.getCertificate(KEY_ALIAS);

    }

}
