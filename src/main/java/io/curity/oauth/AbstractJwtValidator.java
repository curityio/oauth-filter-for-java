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

import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
    private final Set<String> _audiences;
    private final Set<String> _issuers;

    protected AbstractJwtValidator(Set<String> issuers, Set<String> audiences, JsonReaderFactory jsonReaderFactory)
    {
        _issuers = Set.copyOf(issuers);
        _audiences = Set.copyOf(audiences);
        _jsonReaderFactory = jsonReaderFactory;
    }

    protected AbstractJwtValidator(String issuer, String audience, JsonReaderFactory jsonReaderFactory)
    {
        this(Set.of(issuer), Set.of(audience), jsonReaderFactory);
    }

    protected AbstractJwtValidator(String issuer, Set<String> audiences, JsonReaderFactory jsonReaderFactory)
    {
        this(Set.of(issuer), audiences, jsonReaderFactory);
    }

    protected AbstractJwtValidator(Set<String> issuers, String audience, JsonReaderFactory jsonReaderFactory)
    {
        this(issuers, Set.of(audience), jsonReaderFactory);
    }

    public final JsonData validate(String jwt) throws TokenValidationException
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

        validateSignature(jwtHeader, jwtSignature, headerAndPayload);

        try
        {
            long exp = JsonUtils.getLong(jwtBody, "exp");
            long iat = JsonUtils.getLong(jwtBody, "iat");

            Set<String> aud = JsonUtils.getStringOrStrings(jwtBody, "aud");
            String iss = JsonUtils.getString(jwtBody, "iss");

            assert !aud.isEmpty() : "aud claim is not present or is invalid in JWT";
            assert iss != null && !iss.isEmpty() : "iss claim is not present in JWT";

            if (aud.stream().noneMatch(_audiences::contains))
            {
                throw new InvalidAudienceException(String.join(", ", _audiences), String.join(", ", aud));
            }

            if (!_issuers.contains(iss))
            {
                throw new InvalidIssuerException(String.join(", ", _issuers), iss);
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

        return new JsonData(jwtBody);
    }

    private void validateSignature(JwtHeader jwtHeader, byte[] jwtSignatureData,
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
            Optional<PublicKey> signatureVerificationKey = getPublicKey(jwtHeader);

            if (signatureVerificationKey.isEmpty())
            {
                _logger.warning("Received token but could not find matching key");

                throw new UnknownSignatureVerificationKey();
            }

            if (!verifySignature(algorithm, headerAndPayload, jwtSignatureData, signatureVerificationKey.get()))
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
            int integer = input.charAt(i);

            //Since byte is signed in Java we cannot use normal conversion
            //but must drop it into a byte array and truncate.
            byte[] rawBytes = ByteBuffer.allocate(4).putInt(integer).array();
            //Only store the least significant byte (the others should be 0 TODO check)
            bytes[i] = rawBytes[3];
        }

        return bytes;
    }

    private boolean verifySignature(String algorithm, byte[] signingInput, byte[] signature, PublicKey publicKey)
    {
        try
        {
            Signature verifier;
            switch (algorithm)
            {
                case "RS256":
                    verifier = Signature.getInstance("SHA256withRSA");
                    break;
                case "EdDSA":
                    verifier = Signature.getInstance(((EdECPublicKey) publicKey).getParams().getName());
                    break;
                default:
                    throw new UnknownAlgorithmException(String.format("Unsupported signature algorithm '%s'", algorithm));
            }

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
        return "RS256".equals(alg) || "EdDSA".equals(alg);
    }

    private JsonObject decodeJwtBody(String body)
    {
        return _decodedJwtBodyByEncodedBody.computeIfAbsent(body, key ->
        {
            // TODO: Switch to stream
            String decodedBody = new String(Base64.getUrlDecoder().decode(body), StandardCharsets.UTF_8);
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

    static final class JwtHeader
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
