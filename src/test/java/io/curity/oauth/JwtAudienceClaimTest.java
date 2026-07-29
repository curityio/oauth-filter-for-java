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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.assertThrows;

public class JwtAudienceClaimTest
{
    private static final String ISSUER = "test:issuer";
    private static final String KEY_ALIAS = "se.curity.test";

    @Test
    public void testValidatorAcceptsOneAudienceAndTokenHasValidAudienceString() throws Exception
    {
        assertTokenValidation("some:audience",
                keys -> new JwtValidatorWithCert(ISSUER, "some:audience", keys), true);
    }

    @Test
    public void testValidatorAcceptsOneAudienceAndTokenHasValidAudienceArray() throws Exception
    {
        assertTokenValidation(List.of("some:audience", "other:audience"),
                keys -> new JwtValidatorWithCert(ISSUER, "some:audience", keys), true);
    }

    @Test
    public void testValidatorAcceptsOneAudienceAndTokenHasInvalidAudienceString() throws Exception
    {
        assertTokenValidation("some:audience",
                keys -> new JwtValidatorWithCert(ISSUER, "other:audience", keys), false);
    }

    @Test
    public void testValidatorAcceptsOneAudienceAndTokenHasOnlyInvalidAudiencesInArray() throws Exception
    {
        assertTokenValidation(List.of("invalid:audience", "other:invalid:audience"),
                keys -> new JwtValidatorWithCert(ISSUER, "valid:audience", keys), false);
    }

    @Test
    public void testValidatorAcceptsManyAudiencesAndTokenHasValidAudienceString() throws Exception
    {
        assertTokenValidation("valid:audience",
                keys -> new JwtValidatorWithCert(ISSUER, Set.of("valid:audience", "something:else"), keys), true);
    }

    @Test
    public void testValidatorAcceptsManyAudiencesAndTokenHasValidAudiencesArray() throws Exception
    {
        assertTokenValidation(List.of("x", "y", "a"),
                keys -> new JwtValidatorWithCert(ISSUER, Set.of("a", "b"), keys), true);

        assertTokenValidation(List.of("x", "b", "y"),
                keys -> new JwtValidatorWithCert(ISSUER, Set.of("a", "b"), keys), true);

        assertTokenValidation(List.of("a", "b"),
                keys -> new JwtValidatorWithCert(ISSUER, Set.of("a", "b"), keys), true);
    }

    @Test
    public void testValidatorAcceptsManyAudiencesAndTokenHasInvalidAudienceString() throws Exception
    {
        assertTokenValidation("invalid:audience",
                keys -> new JwtValidatorWithCert(ISSUER, Set.of("a", "b"), keys), false);
    }

    @Test
    public void testValidatorAcceptsManyAudiencesAndTokenHasOnlyInvalidAudiencesArray() throws Exception
    {
        assertTokenValidation(List.of("invalid:audience", "other:audience"),
                keys -> new JwtValidatorWithCert(ISSUER, Set.of("a", "b"), keys), false);
    }

    private static void assertTokenValidation(String tokenAudience,
                                       Function<Map<String, PublicKey>, JwtValidator> validatorFactory,
                                       boolean shouldBeValid) throws Exception
    {
        // the token is issued with an array of audiences if there's more than one audience,
        // or with a string audience if there's only one.
        assertTokenValidation(List.of(tokenAudience), validatorFactory, shouldBeValid);
    }

    private static void assertTokenValidation(List<String> tokenAudiences,
                                       Function<Map<String, PublicKey>, JwtValidator> validatorFactory,
                                       boolean shouldBeValid) throws Exception
    {
        TokenFixture fixture = createTokenFixture(tokenAudiences);
        try (JwtValidator validator = validatorFactory.apply(fixture.keys))
        {
            if (shouldBeValid)
            {
                JsonData result = validator.validate(fixture.token);
                assertNotNull(result);
            }
            else
            {
                assertThrows(TokenValidationException.class, () -> validator.validate(fixture.token));
            }
        }
    }

    private static TokenFixture createTokenFixture(List<String> tokenAudiences) throws Exception
    {
        KeyStore keyStore = TestKeyStoreHelper.loadKeyStore();
        PrivateKey privateKey = TestKeyStoreHelper.getPrivateKey(keyStore, KEY_ALIAS);
        Certificate cert = TestKeyStoreHelper.getCertificate(keyStore, KEY_ALIAS);

        JwtTokenIssuer issuer = new JwtTokenIssuer(ISSUER, "RS256", privateKey, cert);
        String tokenWithArrayAudience = issuer.issueToken("testsubject", tokenAudiences, 200, Collections.emptyMap());

        byte[] x5tS256 = DigestUtils.sha256(cert.getEncoded());
        String b64x5tS256 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(x5tS256);
        Map<String, PublicKey> keys = Map.of(b64x5tS256, cert.getPublicKey());
        return new TokenFixture(tokenWithArrayAudience, keys);
    }

    private static class TokenFixture
    {
        private final String token;
        private final Map<String, PublicKey> keys;

        private TokenFixture(String token, Map<String, PublicKey> keys)
        {
            this.token = token;
            this.keys = keys;
        }
    }
}
