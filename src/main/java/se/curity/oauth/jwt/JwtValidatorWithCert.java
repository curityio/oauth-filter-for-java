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

package se.curity.oauth.jwt;

import se.curity.oauth.JsonUtils;

import javax.json.JsonReaderFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

public class JwtValidatorWithCert extends AbstractJwtValidator
{
    private static final Logger _logger = Logger.getLogger(JwtValidatorWithCert.class.getName());

    private final Map<String, RSAPublicKey> _keys;

    JwtValidatorWithCert(Map<String,RSAPublicKey> publicKeys)
    {
        this(publicKeys, JsonUtils.createDefaultReaderFactory());
    }

    JwtValidatorWithCert(Map<String,RSAPublicKey> publicKeys, JsonReaderFactory jsonReaderFactory)
    {
        super(jsonReaderFactory);
        
        _keys = publicKeys;
    }

    /**
     * JWT: abads.gfdr.htefgy
     *
     * @param jwt the original base64 encoded JWT
     * @return True if the JWT is valid
     * @throws IllegalArgumentException if alg or kid are not present in the JWT header.
     * @throws RuntimeException         if some environment issue makes it impossible to validate a signature
     */
    @Override
    public Optional<JwtData> validate(String jwt)
    {
        String[] jwtParts = jwt.split("\\.");

        if (jwtParts.length != 3)
        {
            throw new IllegalArgumentException("Incorrect JWT input");
        }

        String header = jwtParts[0];
        String body = jwtParts[1];
        JwtHeader jwtHeader = decodeJwtHeader(header);

        String alg = jwtHeader.getAlgorithm();

        assert alg != null && alg.length() > 0 : "alg is not present in JWT";

        if (canRecognizeAlg(alg))
        {
            String x5t256 = jwtHeader.getString("x5t#S256");
            Optional<RSAPublicKey> maybeWebKey = getJsonWebKeyForCertThumbprint(x5t256);

            if (maybeWebKey.isPresent())
            {
                byte[] signatureData = Base64.getUrlDecoder().decode(jwtParts[2]);
                byte[] headerAndPayload = convertToBytes(header + "." + jwtParts[1]);

                if (validateSignature(headerAndPayload, signatureData, maybeWebKey.get()))
                {
                    return Optional.of(new JwtData(decodeJwtBody(body)));
                }
            }

            _logger.warning("Received token but could not find matching key");
        }
        else
        {
            _logger.info(() -> String.format("Requested JsonWebKey using unrecognizable alg: %s",
                    jwtHeader.getAlgorithm()));
        }

        return Optional.empty();
    }

    private boolean canRecognizeAlg(String alg)
    {
        return alg.equals("RS256");
    }

    private Optional<RSAPublicKey> getJsonWebKeyForCertThumbprint(String x5t256)
    {
        return Optional.ofNullable(_keys.get(x5t256));
    }
}
