package io.curity.oauth;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EdDSAPublicKeyCreator {

    static PublicKey createPublicKey(String publicKeyJwt) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        byte[] asn1EncodedPublicKey = decoder.decode(publicKeyJwt);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(asn1EncodedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
        return keyFactory.generatePublic(keySpec);
    }

}
