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

import javax.json.JsonReaderFactory;
import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

final class JwtValidatorWithCert extends AbstractJwtValidator
{

    private final Map<String, PublicKey> _keys;

    JwtValidatorWithCert(Set<String> issuers, Set<String> audiences, Map<String, PublicKey> publicKeys)
    {
        this(issuers, audiences, publicKeys, JsonUtils.createDefaultReaderFactory());
    }

    JwtValidatorWithCert(String issuer, Set<String> audiences, Map<String, PublicKey> publicKeys)
    {
        this(Set.of(issuer), audiences, publicKeys);
    }

    JwtValidatorWithCert(Set<String> issuers, String audience, Map<String, PublicKey> publicKeys)
    {
        this(issuers, Set.of(audience), publicKeys);
    }

    JwtValidatorWithCert(String issuer, String audience, Map<String, PublicKey> publicKeys)
    {
        this(Set.of(issuer), audience, publicKeys);
    }

    JwtValidatorWithCert(Set<String> issuers, Set<String> audiences, Map<String, PublicKey> publicKeys,
                         JsonReaderFactory jsonReaderFactory)
    {
        super(issuers, audiences, jsonReaderFactory);

        _keys = publicKeys;
    }

    JwtValidatorWithCert(String issuer, Set<String> audiences, Map<String, PublicKey> publicKeys,
                         JsonReaderFactory jsonReaderFactory)
    {
        this(Set.of(issuer), audiences, publicKeys, jsonReaderFactory);
    }

    JwtValidatorWithCert(Set<String> issuers, String audience, Map<String, PublicKey> publicKeys,
                         JsonReaderFactory jsonReaderFactory)
    {
        this(issuers, Set.of(audience), publicKeys, jsonReaderFactory);
    }

    JwtValidatorWithCert(String issuer, String audience, Map<String, PublicKey> publicKeys,
                         JsonReaderFactory jsonReaderFactory)
    {
        this(Set.of(issuer), audience, publicKeys, jsonReaderFactory);
    }

    @Override
    protected Optional<PublicKey> getPublicKey(JwtHeader jwtHeader)
    {
        return Optional.ofNullable(_keys.get(jwtHeader.getString("x5t#S256")));
    }
}
