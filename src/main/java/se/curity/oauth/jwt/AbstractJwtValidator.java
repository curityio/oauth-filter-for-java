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
import org.apache.commons.codec.binary.Base64;

import javax.json.Json;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.google.common.base.Strings.isNullOrEmpty;

public abstract class AbstractJwtValidator implements JwtValidator
{
    private static final Logger _logger = Logger.getLogger(AbstractJwtValidator.class.getName());

    // Caches with object scope that will ensure that we only decode the same JWT parts once per the lifetime of this object
    private Map<String, JsonObject> _decodedJwtBodyByEncodedBody = new HashMap<>(1);
    private Map<String, JwtHeader> _decodedJwtHeaderByEncodedHeader = new HashMap<>(1);

    @Override
    public Optional<JsonObject> validateAll(String jwt, String audience, String issuer) throws JwtValidationException
    {
        if (validate(jwt).isEmpty())
        {
            return Optional.empty();
        }

        String[] jwtParts = jwt.split("\\.");

        if (jwtParts.length != 3)
        {
            throw new IllegalArgumentException("Incorrect JWT input");
        }

        String body = jwtParts[1];
        Base64 base64 = new Base64(true);

        JsonObject jsonObject = decodeJwtBody(body);

        try
        {
            long exp = getLong(jsonObject, "exp");
            long iat = getLong(jsonObject, "iat");

            String aud = getString(jsonObject, "aud");
            String iss = getString(jsonObject, "iss");

            assert !isNullOrEmpty(aud) : "aud claim is not present in JWT";
            assert !isNullOrEmpty(iss) : "iss claim is not present in JWT";

            if (!aud.equals(audience))
            {
                return Optional.empty();
            }

            if (!iss.equals(issuer))
            {
                return Optional.empty();
            }

            Instant now = Instant.now();

            if (now.getEpochSecond() > exp)
            {
                return Optional.empty();
            }

            if (now.getEpochSecond() < iat)
            {
                return Optional.empty();
            }
        }
        catch (Exception e)
        {
            _logger.log(Level.INFO, "Could not extract token data", e);

            throw new JwtValidationException("Failed to extract data from Token");
        }

        return Optional.of(jsonObject);
    }

    /**
     * Convert base64 to bytes (ASCII)
     *
     * @param input input
     * @return The array of bytes
     */
    byte[] convertToBytes(String input)
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

    boolean validateSignature(byte[] signingInput, byte[] signature, PublicKey publicKey)
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

    PublicKey getKeyFromModAndExp(String modulus, String exponent) throws Exception
    {
        return RsaPublicKeyCreator.createPublicKey(modulus, exponent);
    }

    @Override
    public void close() throws IOException
    {

    }

    JsonObject decodeJwtBody(String body)
    {
        return _decodedJwtBodyByEncodedBody.computeIfAbsent(body, key ->
        {
            // TODO: Switch to stream
            String decodedBody = new String(java.util.Base64.getUrlDecoder().decode(body), Charsets.UTF_8);
            JsonReader jsonBodyReader = Json.createReader(new StringReader(decodedBody));

            return jsonBodyReader.readObject();
        });
    }

    JwtHeader decodeJwtHeader(String header)
    {
        return _decodedJwtHeaderByEncodedHeader.computeIfAbsent(header, key ->
        {
            Base64 base64 = new Base64(true);
            String decodedHeader = new String(base64.decode(header), Charsets.UTF_8);
            JsonReader jsonHeaderReader = Json.createReader(new StringReader(decodedHeader));

            return new JwtHeader(jsonHeaderReader.readObject());
        });
    }

    private String getString(JsonObject jsonObject, String name)
    {
        return Optional.ofNullable(jsonObject.get(name))
                .filter(it -> it.getValueType() == JsonValue.ValueType.STRING)
                .map(it -> ((JsonString) it).getString())
                .orElse(null);
    }

    private static long getLong(JsonObject jsonObject, String name)
    {
        return Optional.ofNullable(jsonObject.get(name))
                .filter(it -> it.getValueType() == JsonValue.ValueType.NUMBER)
                .map(it -> ((JsonNumber) it).longValue())
                .orElse(Long.MIN_VALUE);
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
            return AbstractJwtValidator.this.getString(_jsonObject, name);
        }
    }
}
