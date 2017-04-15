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

import org.apache.http.client.HttpClient;

import javax.json.JsonObject;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * A validator class that does not depend on any external libraries
 */
public final class JwtValidatorWithJwk extends AbstractJwtValidator
{
    private static final Logger _logger = Logger.getLogger(JwtValidatorWithJwk.class.getName());

    private final JwkManager _jwkManager;

    public JwtValidatorWithJwk(URI webKeysURI, long minKidReloadTime, HttpClient httpClient)
    {
        _jwkManager = new JwkManager(webKeysURI, minKidReloadTime, httpClient);
    }

    /**
     * JWT: abads.gfdr.htefgy
     *
     * @param jwt the original base64 encoded JWT
     * @return A map with the content of the Jwt body if the JWT is valid, otherwise null
     * @throws IllegalArgumentException if alg or kid are not present in the JWT header.
     * @throws RuntimeException         if some environment issue makes it impossible to validate a signature
     */
    public JsonObject validate(String jwt) throws JwtValidationException
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
        String kid = jwtHeader.getKeyId();

        assert alg != null && alg.length() > 0 : "Alg is not present in JWT";
        assert kid != null && kid.length() > 0 : "Key ID is not present in JWT";

        if (canRecognizeAlg(alg))
        {
            try
            {
                Optional<JsonWebKey> maybeWebKey = getJsonWebKeyFor(kid);

                if (maybeWebKey.isPresent())
                {
                    byte[] signatureData = Base64.getUrlDecoder().decode(jwtParts[2]);
                    byte[] headerAndPayload = convertToBytes(header + "." + jwtParts[1]);

                    if(validateSignature(headerAndPayload,
                            signatureData,
                            getKeyFromModAndExp(maybeWebKey.get().getModulus(), maybeWebKey.get().getExponent())))
                    {
                        return decodeJwtBody(body);
                    }
                }
            }
            catch(Exception e)
            {
                throw new JwtValidationException("Unable to validate Jwt ", e);
            }
        }
        else
        {
            _logger.info(() -> String.format("Requested JsonWebKey using unrecognizable alg: %s",
                    jwtHeader.getAlgorithm()));
        }

        return null;
    }

    private Optional<JsonWebKey> getJsonWebKeyFor(String kid)
    {
        try
        {
            return Optional.ofNullable(_jwkManager.getJsonWebKeyForKeyId(kid));
        }
        catch (JsonWebKeyNotFoundException e)
        {
            // this is not a very exceptional occurrence, so let's not log a stack-trace
            _logger.info(() -> String.format("Could not find requested JsonWebKey: %s", e));

            return Optional.empty();
        }
    }

    private boolean canRecognizeAlg(String alg)
    {
        return alg.equals("RS256");
    }

    @Override
    public void close() throws IOException
    {
        _jwkManager.close();
    }
}
