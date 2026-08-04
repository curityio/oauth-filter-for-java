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

import org.junit.Test;

import java.security.PublicKey;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.assertThrows;

public class JwtIssuerClaimTest
{
    private static final String AUDIENCE = "test:audience";

    @Test
    public void testValidatorAcceptsOneIssuerAndTokenHasValidIssuer() throws Exception
    {
        assertTokenValidation("some:issuer", keys -> new JwtValidatorWithCert("some:issuer", AUDIENCE, keys), true);
    }

    @Test
    public void testValidatorAcceptsOneIssuerAndTokenHasInvalidIssuer() throws Exception
    {
        assertTokenValidation("other:issuer", keys -> new JwtValidatorWithCert("some:issuer", AUDIENCE, keys), false);
    }

    @Test
    public void testValidatorAcceptsManyIssuersAndTokenHasValidIssuer() throws Exception
    {
        assertTokenValidation("valid:issuer",
                keys -> new JwtValidatorWithCert(Set.of("valid:issuer", "other:issuer"), AUDIENCE, keys), true);
    }

    @Test
    public void testValidatorAcceptsManyIssuersAndTokenHasInvalidIssuer() throws Exception
    {
        assertTokenValidation("invalid:issuer",
                keys -> new JwtValidatorWithCert(Set.of("valid:issuer", "other:issuer"), AUDIENCE, keys), false);
    }

    private static void assertTokenValidation(String tokenIssuer,
                                              Function<Map<String, PublicKey>, JwtValidator> validatorFactory,
                                              boolean shouldBeValid) throws Exception
    {
        JwtTokenFixtureHelper.TokenFixture fixture = JwtTokenFixtureHelper.createTokenFixture(tokenIssuer, AUDIENCE);
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
}
