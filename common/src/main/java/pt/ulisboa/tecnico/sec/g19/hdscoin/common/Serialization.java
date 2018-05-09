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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


public class Serialization {

    // paths
    public static final String CLIENT_PACKAGE_PATH =
            "\\src\\main\\java\\pt\\ulisboa\\tecnico\\sec\\g19\\hdscoin\\client";
    public static final String SERVER_PACKAGE_PATH =
            "\\src\\main\\java\\pt\\ulisboa\\tecnico\\sec\\g19\\hdscoin\\server";
    public static final String COMMON_PACKAGE_PATH =
            "\\src\\main\\java\\pt\\ulisboa\\tecnico\\sec\\g19\\hdscoin\\common";
    public static final String KEY_STORE_FILE_NAME = "keystore.ks";
    // key store password explicitly here for simplicity, each alias has its own password
    public static final String KEY_STORE__PASSWORD = "ABCDEF";
    public static final String SERVER_PREFIX = "Server_";
    public static final String CLIENT_PREFIX = "Client_";
    public static final String SIGNATURE_HEADER_NAME = "SIGNATURE";
    public static final String NONCE_HEADER_NAME = "NONCE";
    private static ObjectMapper mapper = new ObjectMapper ();

    /**
     * Deserializes a request into the specified class
     *
     * @param request   the request to deserialize
     * @param valueType the expected object class
     *
     * @return the read object
     *
     * @throws IOException
     */
    public static <T> T parse (Request request, Class<T> valueType) throws IOException {
        return parse (request.body (), valueType);
    }

    /**
     * Deserializes a request into the specified class
     *
     * @param request   the string to deserialize
     * @param valueType the expected object class
     *
     * @return the  read object
     *
     * @throws IOException
     */
    public static <T> T parse (String request, Class<T> valueType) throws IOException {
        return mapper.readValue (request, valueType);
    }

    public static String serialize (Object obj) throws JsonProcessingException {
        return mapper.writeValueAsString (obj);
    }

    /**
     * Takes a EC public key encoded in base 64 and decodes it
     *
     * @param base64key the base 64 key to decode
     *
     * @return the decoded ECPublicKey
     *
     * @throws KeyException if an error occurs deserializing the key
     */
    public static ECPublicKey base64toPublicKey (String base64key) throws KeyException {
        byte[] keyBytes = Base64.getDecoder ().decode (base64key);
        try {
            X509EncodedKeySpec ks = new X509EncodedKeySpec (keyBytes);
            KeyFactory kf = KeyFactory.getInstance ("EC");
            ECPublicKey publicKey = (ECPublicKey) kf.generatePublic (ks);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyException (e);
        }
    }

    public static ECPrivateKey base64toPrivateKey (String base64key) throws KeyException {
        byte[] keyBytes = Base64.getDecoder ().decode (base64key);
        try {
            final KeyFactory kf = KeyFactory.getInstance ("EC", "BC");
            final PKCS8EncodedKeySpec encPrivKeySpec = new PKCS8EncodedKeySpec (keyBytes);
            return (ECPrivateKey) kf.generatePrivate (encPrivKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new KeyException (e);
        }
    }

    /**
     * Takes a EC public key and encodes it in base64
     *
     * @param key the ECPublicKey to encode
     *
     * @return the encoded key in base 64
     *
     * @throws KeyException if an error occurs serializing the key
     */
    public static String publicKeyToBase64 (ECPublicKey key) throws KeyException {
        return Base64.getEncoder ().encodeToString (key.getEncoded ());
    }

    public static String privateKeyToBase64 (ECPrivateKey key) throws KeyException {
        return Base64.getEncoder ().encodeToString (key.getEncoded ());
    }


    public enum StatusMessage {
        SUCCESS, ERROR_INVALID_LEDGER, ERROR_INVALID_AMOUNT, ERROR_NO_SIGNATURE_MATCH, ERROR_INVALID_KEY,
        ERROR_MISSING_PARAMETER, ERROR_INVALID_VALUE, ERROR_SERVER_ERROR
    }


    public static class RegisterRequest implements Signable, NonceContainer {

        public Transaction initialTransaction;

        @Override @JsonIgnore public String getSignable () {
            return initialTransaction.getSignable ();
        }

        @Override @JsonIgnore public String getNonce () {
            return initialTransaction.getNonce ();
        }
    }


    ////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////


    public static class SendAmountRequest implements Signable, NonceContainer {// extends Transaction {
        public Ledger ledger;
        public Transaction transaction;

        public SendAmountRequest () {
            transaction = new Serialization.Transaction ();
            transaction.isSend = true;
        }

        @Override @JsonIgnore public String getSignable () {
            return transaction.getSignable () + ledger.getSignable ();
        }

        @Override @JsonIgnore public String getNonce () {
            return transaction.getNonce ();
        }

    }


    public static class ReceiveAmountRequest implements Signable, NonceContainer {
        //public
        public String pendingTransactionHash;
        public Transaction transaction;
        public Ledger ledger;

        @Override @JsonIgnore public String getSignable () {
            return transaction.getSignable () + pendingTransactionHash + ledger.getSignable ();
        }

        @Override @JsonIgnore public String getNonce () {
            return transaction.getNonce ();
        }
    }

    // this is NOT Signable, so that audits can be performed without the private key of the ledger
    // transactions in the ledger have signatures that can be verified independently by who receives the request (server)
    public static class WriteBackRequest implements NonceContainer {
        public Ledger ledger;
        public String nonce;

        @Override public String getNonce () {
            return nonce;
        }

    }


    public static class Response implements Signable, NonceContainer {

        public int statusCode = -1;
        public StatusMessage status;
        public String nonce = ""; // nonce that the client sent and now we send back, as part of what's signed

        @Override @JsonIgnore public String getSignable () {
            return status + nonce;
        }

        @Override public String getNonce () {
            return nonce;
        }
    }


    public static class CheckAccountResponse extends Response implements Signable, Readable {
        public int balance;
        public List<Transaction> pendingTransactions = new ArrayList<> ();
        public int timestamp;

        @Override @JsonIgnore public String getSignable () {
            StringBuilder signable = new StringBuilder (super.getSignable ()).append (balance);
            for (Transaction tx : pendingTransactions) {
                signable.append (tx.getSignable ());
            }
            return signable.toString ();
        }

        @Override public int getTimestamp () {
            return timestamp;
        }
    }


    public static class AuditResponse extends Response implements Signable, Readable {
        public Ledger ledger;

        @Override @JsonIgnore public String getSignable () {
            StringBuilder signable = new StringBuilder (super.getSignable ());
            signable.append (ledger.timestamp)
                    .append (ledger.getSignable ());
            return signable.toString ();
        }

        @Override @JsonIgnore public int getTimestamp () {
            return ledger.timestamp;
        }
    }


    public static class Transaction implements Signable, NonceContainer {

        public String source;
        public String target; // who receives the money
        public boolean isSend;
        public int amount;
        public String nonce;
        public String previousSignature;
        public String signature;

        @Override @JsonIgnore public String getSignable () {
            return source + target + Boolean.toString (isSend) + Integer.toString (amount) + nonce + previousSignature;
        }

        @Override public String getNonce () {
            return nonce;
        }

        @Override @JsonIgnore public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("\n-----------------------------\n");
            builder.append("\t\tTransaction\n");
            builder.append("\t\t-----------\n");
            builder.append("Source: " + source).append ("\n");
            builder.append("Target: " + target).append ("\n");
            builder.append("Amount: ").append(this.amount).append(" HDS Coins\n");
            builder.append("Nonce: ").append(this.nonce).append("\n");
            builder.append("Signature prev. Transaction: ").append(this.previousSignature).append("\n");
            builder.append("Signature: ").append(this.signature).append("\n");
            builder.append("Get Signable: ").append(getSignable ()).append("\n");
            builder.append("-----------------------------");
            return builder.toString();
        }
    }


    public static class Ledger implements Signable {
        public int timestamp;
        public List<Transaction> transactions = new ArrayList<> ();

        @Override @JsonIgnore public String getSignable () {
            StringBuilder signable = new StringBuilder ();
            signable.append (timestamp);
            for (Transaction tx : transactions) {
                signable.append (tx.getSignable ());
            }
            return signable.toString ();
        }
    }
}
