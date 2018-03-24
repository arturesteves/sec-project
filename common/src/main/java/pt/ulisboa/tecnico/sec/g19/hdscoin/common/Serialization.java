package pt.ulisboa.tecnico.sec.g19.hdscoin.common;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import spark.Request;

import java.io.IOException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Serialization {
    private static ObjectMapper mapper = new ObjectMapper();

    public static class RegisterRequest implements Signable {
        public String key;
        public int amount;

        @Override
        @JsonIgnore
        public String getSignable() {
            return key + Integer.toString(amount);
        }
    }

    private static abstract class TransactionRequest implements Signable {
        public String source;
        public String destination; // who receives the money
        public int amount;
        public String previousSignature;

        @Override
        @JsonIgnore
        public String getSignable() {
            // true: because is_send = true
            return source + destination + Boolean.toString(true) + Integer.toString(amount) + previousSignature;
        }
    }

    public static class SendAmountRequest extends TransactionRequest implements Signable {
        @Override
        @JsonIgnore
        public String getSignable() {
            // true: because is_send = true
            return super.getSignable() + Boolean.toString(true);
        }
    }

    public static class ReceiveAmountRequest extends TransactionRequest implements Signable {
        @Override
        @JsonIgnore
        public String getSignable() {
            // false: because is_send = false
            return super.getSignable() + Boolean.toString(false);
        }
    }

    public static class Response implements Signable, NonceContainer {
        @JsonIgnore
        public int statusCode = -1;

        public String status; // "ok" or "error"
        public String nonce; // nonce that the client sent and now we send back, as part of what's signed

        @Override
        @JsonIgnore
        public String getSignable() {
            return status + nonce;
        }

        @Override
        public String getNonce() {
            return nonce;
        }
    }

    /**
     * Deserializes a request into the specified class
     *
     * @param request   the request to deserialize
     * @param valueType the expected object class
     * @return the read object
     * @throws IOException
     */
    public static <T> T parse(Request request, Class<T> valueType) throws IOException {
        return parse(request.body(), valueType);
    }

    /**
     * Deserializes a request into the specified class
     *
     * @param request   the string to deserialize
     * @param valueType the expected object class
     * @return the read object
     * @throws IOException
     */
    public static <T> T parse(String request, Class<T> valueType) throws IOException {
        return mapper.readValue(request, valueType);
    }

    public static String serialize(Object obj) throws JsonProcessingException {
        return mapper.writeValueAsString(obj);
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
}
