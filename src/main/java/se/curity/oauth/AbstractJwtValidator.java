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

import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

abstract class AbstractJwtValidator implements JwtValidator
{
    private static final Logger _logger = Logger.getLogger(AbstractJwtValidator.class.getName());

    // Caches with object scope that will ensure that we only decode the same JWT parts once per the lifetime of this
    // object
    private final Map<String, JsonObject> _decodedJwtBodyByEncodedBody = new HashMap<>(1);
    private final Map<String, JwtHeader> _decodedJwtHeaderByEncodedHeader = new HashMap<>(1);
    private final JsonReaderFactory _jsonReaderFactory;
    private final String _audience;
    private final String _issuer;

    AbstractJwtValidator(String issuer, String audience, JsonReaderFactory jsonReaderFactory)
    {
        _issuer = issuer;
        _audience = audience;
        _jsonReaderFactory = jsonReaderFactory;
    }

    public final JwtData validate(String jwt) throws TokenValidationException
    {
        String[] jwtParts = jwt.split("\\.");

        if (jwtParts.length != 3)
        {
            throw new InvalidTokenFormatException();
        }

        JsonObject jwtBody = decodeJwtBody(jwtParts[1]);
        JwtHeader jwtHeader = decodeJwtHeader(jwtParts[0]);
        byte[] jwtSignature = Base64.getUrlDecoder().decode(jwtParts[2]);
        byte[] headerAndPayload = convertToBytes(jwtParts[0] + "." + jwtParts[1]);

        validateSignature(jwtHeader, jwtBody, jwtSignature, headerAndPayload);

        try
        {
            long exp = JsonUtils.getLong(jwtBody, "exp");
            long iat = JsonUtils.getLong(jwtBody, "iat");

            String aud = JsonUtils.getString(jwtBody, "aud");
            String iss = JsonUtils.getString(jwtBody, "iss");

            assert aud != null && aud.length() > 0 : "aud claim is not present in JWT";
            assert iss != null && iss.length() > 0 : "iss claim is not present in JWT";

            if (!aud.equals(_audience))
            {
                throw new InvalidAudienceException(_audience, aud);
            }

            if (!iss.equals(_issuer))
            {
                throw new InvalidIssuerException(_issuer, iss);
            }

            Instant now = Instant.now();

            if (now.getEpochSecond() > exp)
            {
                throw new ExpiredTokenException();
            }

            if (now.getEpochSecond() < iat)
            {
                throw new InvalidIssuanceInstantException();
            }
        }
        catch (Exception e)
        {
            _logger.log(Level.INFO, "Could not extract token data", e);

            throw new InvalidTokenFormatException("Failed to extract data from Token");
        }

        return new JwtData(jwtBody);
    }

    private void validateSignature(JwtHeader jwtHeader, JsonObject jwtBody, byte[] jwtSignatureData,
                                   byte[] headerAndPayload)
            throws TokenValidationException
    {
        String algorithm = jwtHeader.getAlgorithm();

        if (algorithm == null || algorithm.length() <= 0)
        {
            throw new MissingAlgorithmException();
        }

        if (canRecognizeAlg(algorithm))
        {
            Optional<PublicKey> maybeKey = getPublicKey(jwtHeader);

            if (!maybeKey.isPresent())
            {
                _logger.warning("Received token but could not find matching key");

                throw new UnknownSignatureVerificationKey();
            }

            if (!verifySignature(headerAndPayload, jwtSignatureData, maybeKey.get()))
            {
                throw new InvalidSignatureException();
            }
        }
        else
        {
            _logger.warning(() -> String.format("Requested JsonWebKey using unrecognizable alg: %s", algorithm));

            throw new UnknownAlgorithmException(algorithm);
        }
    }

    protected abstract Optional<PublicKey> getPublicKey(JwtHeader jwtHeader);

    /**
     * Convert base64 to bytes (ASCII)
     *
     * @param input input
     * @return The array of bytes
     */
    private byte[] convertToBytes(String input)
    {
        byte[] bytes = new byte[input.length()];

        for (int i = 0; i < input.length(); i++)
        {
            //Convert and treat as ascii.
            int integer = (int) input.charAt(i);

            //Since byte is signed in Java we cannot use normal conversion
            //but must drop it into a byte array and truncate.
            byte[] rawBytes = ByteBuffer.allocate(4).putInt(integer).array();
            //Only store the least significant byte (the others should be 0 TODO check)
            bytes[i] = rawBytes[3];
        }

        return bytes;
    }

    private boolean verifySignature(byte[] signingInput, byte[] signature, PublicKey publicKey)
    {
        try
        {
            Signature verifier = Signature.getInstance("SHA256withRSA");

            verifier.initVerify(publicKey);
            verifier.update(signingInput);

            return verifier.verify(signature);
        }
        catch (Exception e)
        {
            throw new RuntimeException("Unable to validate JWT signature", e);
        }
    }

    private boolean canRecognizeAlg(String alg)
    {
        return alg.equals("RS256");
    }

    private JsonObject decodeJwtBody(String body)
    {
        return _decodedJwtBodyByEncodedBody.computeIfAbsent(body, key ->
        {
            // TODO: Switch to stream
            String decodedBody = new String(java.util.Base64.getUrlDecoder().decode(body), StandardCharsets.UTF_8);
            JsonReader jsonBodyReader = _jsonReaderFactory.createReader(new StringReader(decodedBody));

            return jsonBodyReader.readObject();
        });
    }

    private JwtHeader decodeJwtHeader(String header)
    {
        return _decodedJwtHeaderByEncodedHeader.computeIfAbsent(header, key ->
        {
            Base64.Decoder base64 = Base64.getDecoder();
            String decodedHeader = new String(base64.decode(header), StandardCharsets.UTF_8);
            JsonReader jsonHeaderReader = _jsonReaderFactory.createReader(new StringReader(decodedHeader));

            return new JwtHeader(jsonHeaderReader.readObject());
        });
    }

    class JwtHeader
    {
        private final JsonObject _jsonObject;

        JwtHeader(JsonObject jsonObject)
        {
            _jsonObject = jsonObject;
        }

        String getAlgorithm()
        {
            return getString("alg");
        }

        String getKeyId()
        {
            return getString("kid");
        }

        String getString(String name)
        {
            return JsonUtils.getString(_jsonObject, name);
        }
    }
}
