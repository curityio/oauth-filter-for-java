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

import com.owlike.genson.Genson;
import com.owlike.genson.GensonBuilder;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.ReservedClaimNames;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class JwtTokenIssuer
{
    private static final Log _logger = LogFactory.getLog(JwtTokenIssuer.class);

    private final int _skewTolerance;
    private final String _issuer;
    private final String _algorithm;
    private final PrivateKey _privateKey;
    private final Certificate _cert;
    private final String _keyId;

    private final Genson _genson = new GensonBuilder().setHtmlSafe(false).create();

    //Issue Unsigned token.
    public JwtTokenIssuer(String issuer)
    {
        this(issuer, 0, AlgorithmIdentifiers.NONE, null, null, null);
    }

    //Certs
    JwtTokenIssuer(String issuer, PrivateKey privateKey, Certificate cert)
    {
        this(issuer, 0, AlgorithmIdentifiers.RSA_USING_SHA256, privateKey, cert, null);
    }

    //JWKS
    public JwtTokenIssuer(String issuer, PrivateKey privateKey, String keyId)
    {
        this(issuer, 0, AlgorithmIdentifiers.RSA_USING_SHA256, privateKey, null, keyId);
    }

    //Certs
    public JwtTokenIssuer(String issuer, String algorithm, PrivateKey privateKey, Certificate cert)
    {
        this(issuer, 0, algorithm, privateKey, cert, null);
    }

    //JWKS
    public JwtTokenIssuer(String issuer, String algorithm, PrivateKey privateKey, String keyId)
    {
        this(issuer, 0, algorithm, privateKey, null, keyId);
    }

    //The full constructor
    private JwtTokenIssuer(String issuer, int skewTolerance, String algorithm, PrivateKey privateKey, Certificate
            cert, String keyId)
    {
        _issuer = issuer;
        _skewTolerance = skewTolerance * 60;
        _algorithm = algorithm;
        _privateKey = privateKey;
        _cert = cert;
        _keyId = keyId;
    }

    String issueToken(String subject, String audience, int lifetimeInMinutes, Map<String, Object> attributes)
            throws Exception
    {
        String[] audiences = stringToArray(audience);

        return issueToken(subject, Arrays.asList(audiences), lifetimeInMinutes, attributes);
    }

    private String issueToken(String subject, List<String> audiences, int lifetimeInMinutes, Map<String, Object>
            attributes)
            throws Exception
    {
        Map<String, Object> claims = new LinkedHashMap<>();

        //Store the initial attributes
        for (String key : attributes.keySet())
        {
            claims.put(key, attributes.get(key));
        }

        JsonWebSignature token = new JsonWebSignature();

        if (AlgorithmIdentifiers.NONE.equals(this._algorithm) && _privateKey == null)
        {
            token.setAlgorithmConstraints(AlgorithmConstraints.ALLOW_ONLY_NONE);
        }

        long issuedAt = Instant.now().getEpochSecond();
        long expirationTime = lifetimeInMinutes * 60 + issuedAt + _skewTolerance;

        claims.put(ReservedClaimNames.ISSUER, _issuer);
        claims.put(ReservedClaimNames.SUBJECT, subject);
        claims.put(ReservedClaimNames.AUDIENCE, arrayOrString(audiences));

        claims.put(ReservedClaimNames.ISSUED_AT, issuedAt);
        claims.put(ReservedClaimNames.NOT_BEFORE, issuedAt - _skewTolerance);
        claims.put(ReservedClaimNames.EXPIRATION_TIME, expirationTime);
        claims.put(ReservedClaimNames.JWT_ID, UUID.randomUUID().toString());

        String payload = _genson.serialize(claims);

        token.setHeader(ReservedClaimNames.ISSUER, _issuer);

        try
        {
            if (this._cert != null)
            {
                byte[] x5t = DigestUtils.sha(this._cert.getEncoded());
                byte[] x5tS256 = DigestUtils.sha256(this._cert.getEncoded());

                //Set DER encoded base64urlsafe string as header params
                String b64x5t = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(x5t);
                String b64x5tS256 = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(x5tS256);

                token.setHeader("x5t", b64x5t);
                token.setHeader("x5t#S256", b64x5tS256);

                _logger.trace("x5t: " + b64x5t);
                _logger.trace("x5t#256: " + b64x5tS256);
            }
            else if (this._keyId != null)
            {
                token.setKeyIdHeaderValue(this._keyId);
            }
        }
        catch (CertificateEncodingException ce)
        {
            throw new Exception("Unknown certificate encoding", ce);
        }

        token.setPayload(payload);

        if (_privateKey != null)
        {
            token.setKey(_privateKey);     //Can be null for "none" algorithm
        }

        token.setAlgorithmHeaderValue(_algorithm);

        try
        {
            String serializedToken = token.getCompactSerialization();

            _logger.trace("Serialized Token: " + serializedToken);

            if (_logger.isTraceEnabled())
            {
                //With jose4j version 0.3.4 the getPayload will perform a Verify operation
                //This requires the Public Key to be set as the Key.
                if (this._cert != null)
                {
                    token.setKey(_cert.getPublicKey());
                    String headers = token.getHeader();
                    String body = token.getPayload();
                    String maskedToken = serializedToken.length() >= 20 ? serializedToken.substring(0, 10) : "";

                    String message = String.format("Issuing token: %s******\nHeader = %s\nBody = %s",
                            maskedToken, headers, body);

                    _logger.trace(message);
                }
                
                _logger.trace(serializedToken);
            }

            return serializedToken;
        }
        catch (JoseException e)
        {
            _logger.error("Could not issue token", e);

            throw new Exception("Could not issue a JWT token. See inner exception for details", e);
        }
    }

    private String[] stringToArray(String str)
    {
        String[] ret;
        ret = str.split(" ");
        return ret;
    }

    private Object arrayOrString(List data)
    {
        if (data.size() == 1)
        {
            return data.get(0);
        }
        
        return data;
    }
}
