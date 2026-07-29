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
import org.junit.Test;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Map;

import static junit.framework.TestCase.assertNotNull;

public class JwtAudienceClaimTest
{
    private static final String ISSUER = "test:issuer";
    private static final String AUDIENCE = "foo:audience";
    private static final String KEY_ALIAS = "se.curity.test";

    @Test
    public void testAudienceClaimAsJsonArray() throws Exception
    {
        KeyStore keyStore = TestKeyStoreHelper.loadKeyStore();
        PrivateKey privateKey = TestKeyStoreHelper.getPrivateKey(keyStore, KEY_ALIAS);
        Certificate cert = TestKeyStoreHelper.getCertificate(keyStore, KEY_ALIAS);

        JwtTokenIssuer issuer = new JwtTokenIssuer(ISSUER, "RS256", privateKey, cert);
        String tokenWithArrayAudience = issuer.issueToken("testsubject", AUDIENCE + " other:audience", 200,
                Collections.emptyMap());

        byte[] x5tS256 = DigestUtils.sha256(cert.getEncoded());
        String b64x5tS256 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(x5tS256);
        Map<String, PublicKey> keys = Map.of(b64x5tS256, cert.getPublicKey());

        JwtValidator validator = new JwtValidatorWithCert(ISSUER, AUDIENCE, keys);
        JsonData result = validator.validate(tokenWithArrayAudience);

        assertNotNull(result);
    }
}
