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

package se.curity.oauth;

import javax.json.JsonReaderFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

final class JwtValidatorWithCert extends AbstractJwtValidator
{
    private static final Logger _logger = Logger.getLogger(JwtValidatorWithCert.class.getName());

    private final Map<String, RSAPublicKey> _keys;

    JwtValidatorWithCert(String issuer, String audience, Map<String, RSAPublicKey> publicKeys)
    {
        this(issuer, audience, publicKeys, JsonUtils.createDefaultReaderFactory());
    }

    JwtValidatorWithCert(String issuer, String audience, Map<String, RSAPublicKey> publicKeys,
                         JsonReaderFactory jsonReaderFactory)
    {
        super(issuer, audience, jsonReaderFactory);
        
        _keys = publicKeys;
    }

    @Override
    protected Optional<PublicKey> getPublicKey(JwtHeader jwtHeader)
    {
        return Optional.ofNullable(_keys.get(jwtHeader.getString("x5t#S256")));
    }
}
