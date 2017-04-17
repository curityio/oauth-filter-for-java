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

class InvalidTokenFormatException extends TokenValidationException
{
    private static final String _message = "Invalid token format";

    InvalidTokenFormatException()
    {
        super(_message);
    }

    InvalidTokenFormatException(String msg)
    {
        super(msg);
    }
}

class MissingAlgorithmException extends TokenValidationException
{
    private static final String _message = "No algorithm was provided in the token";

    MissingAlgorithmException()
    {
        super(_message);
    }
}

class InvalidAudienceException extends TokenValidationException
{
    private static final String _formattedMessage = "Audience %s does not match expected one %s";

    InvalidAudienceException(String expectedAudience, String actualAudience)
    {
        super(String.format(_formattedMessage, actualAudience, expectedAudience));
    }
}

class InvalidSignatureException extends TokenValidationException
{
    private static final String _message = "The signature of the given token did not match the computed one";

    InvalidSignatureException()
    {
        super(_message);
    }
}

class InvalidIssuanceInstantException extends TokenValidationException
{
    private static final String _message = "The token is invalid because it was issued in the past";

    InvalidIssuanceInstantException()
    {
        super(_message);
    }
}

class ExpiredTokenException extends TokenValidationException
{
    private static final String _message = "The token is invalid because it is expired";

    ExpiredTokenException()
    {
        super(_message);
    }
}

class RevokedTokenException extends TokenValidationException
{
    private static final String _message = "The token is invalid because it has been revoked";

    RevokedTokenException()
    {
        super(_message);
    }
}

class UnknownAlgorithmException extends InvalidTokenFormatException
{
    private static final String _formattedMessage = "The algorithm %s is not recognized";

    UnknownAlgorithmException(String unrecognizedAlgorithm)
    {
        super(String.format(_formattedMessage, unrecognizedAlgorithm));
    }
}

class InvalidIssuerException extends TokenValidationException
{
    private static final String _formattedMessage = "Issuer %s does not match expected one %s";

    InvalidIssuerException(String expectedIssuer, String actualIssuer)
    {
        super(String.format(_formattedMessage, actualIssuer, expectedIssuer));
    }
}

class UnknownSignatureVerificationKey extends TokenValidationException
{
    private static final String _message = "The key used to sign the token is unknown and untrusted";

    UnknownSignatureVerificationKey()
    {
        super(_message);
    }
}
