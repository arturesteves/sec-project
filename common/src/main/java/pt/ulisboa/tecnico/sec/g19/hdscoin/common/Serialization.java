package pt.ulisboa.tecnico.sec.g19.hdscoin.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import spark.Request;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Serialization {
    private static ObjectMapper mapper = new ObjectMapper();

    public static class RegisterRequest {
        public String key;
        public int amount;
    }

    public static class SendAmountRequest {
        // TODO add remaining fields
        public String source;
        public String destination;
        public int amount;
    }

    public static class ReceiveAmountRequest {
        // TODO add remaining fields
        public String source;

    }

    /**
     * Deserializes a request into the specified class
     * @param request the request to deserialize
     * @param valueType the expected object class
     * @return the read object
     * @throws IOException
     */
    public static <T> T parse(Request request, Class<T> valueType) throws IOException {
        return mapper.readValue(request.body(), valueType);
    }

    /**
     * Takes a EC public key encoded in base 64 and decodes it
     *
     * @param base64key the base 64 key to decode
     * @return the decoded ECPublicKey
     * @throws KeyException if an error occurs deserializing the key
     */
    public static ECPublicKey base64toPublicKey(String base64key) throws KeyException {
        byte[] keyBytes = Base64.getDecoder().decode(base64key);
        try {
            X509EncodedKeySpec ks = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(ks);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyException(e);
        }
    }

    public static ECPrivateKey base64toPrivateKey(String base64key) throws KeyException {
        byte[] keyBytes = Base64.getDecoder().decode(base64key);
        try {
            final KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            final PKCS8EncodedKeySpec encPrivKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            return (ECPrivateKey) kf.generatePrivate(encPrivKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new KeyException(e);
        }
    }

    /**
     * Takes a EC public key and encodes it in base64
     *
     * @param key the ECPublicKey to encode
     * @return the encoded key in base 64
     * @throws KeyException if an error occurs serializing the key
     */
    public static String publicKeyToBase64(ECPublicKey key) throws KeyException {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String privateKeyToBase64(ECPrivateKey key) throws KeyException {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecGenSpec, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }
}
