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

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Strings.isNullOrEmpty;

public class JwtValidatorWithCert extends AbstractJwtValidator
{
    private static final Logger _logger = LoggerFactory.getLogger(JwtValidatorWithCert.class);

    private final Gson _gson = new GsonBuilder()
            .disableHtmlEscaping()
            .create();

    private final Map<String, RSAPublicKey> _keys;

    public JwtValidatorWithCert(Map<String,RSAPublicKey> publicKeys)
    {
        this._keys = publicKeys;
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
    public Map<String, Object> validate(String jwt)
    {
        String[] jwtParts = jwt.split("\\.");

        if (jwtParts.length != 3)
        {
            throw new IllegalArgumentException("Incorrect JWT input");
        }

        String header = jwtParts[0];
        String body = jwtParts[1];
        byte[] headerAndPayload = convertToBytes(header + "." + jwtParts[1]);
        Base64 base64 = new Base64(true);

        @SuppressWarnings("unchecked")
        Map<String, String> headerMap = _gson.fromJson(
                new String(base64.decode(header), Charsets.UTF_8), Map.class);

        String alg = headerMap.get("alg");
        String x5t256 = headerMap.get("x5t#S256");

        Preconditions.checkArgument(!isNullOrEmpty(alg), "alg is not present in JWT");

        if (canRecognizeAlg(alg))
        {
            Optional<RSAPublicKey> maybeWebKey = getJsonWebKeyForCertThumbprint(x5t256);

            if (maybeWebKey.isPresent())
            {
                byte[] signatureData = base64.decode(jwtParts[2]);

                if (validateSignature(headerAndPayload, signatureData, maybeWebKey.get()))
                {
                    Map<?, ?> map = _gson.fromJson(new String(base64.decode(body), Charsets.UTF_8), Map.class);
                    Map<String, Object> result = new LinkedHashMap<>(map.size());

                    for (Map.Entry entry : map.entrySet())
                    {
                        result.put(entry.getKey().toString(), entry.getValue());
                    }

                    return result;
                }
            }

            _logger.warn("Received token but could not find matching key");
        }
        else
        {
            _logger.info("Requested JsonWebKey using unrecognizable alg: {}", headerMap.get("alg"));
        }

        return null;
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
