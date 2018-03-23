package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.kevinsawicki.http.HttpRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Client implements IClient {

    private URL url;
    private ECPublicKey serverPublicKey;

    static {
         Security.addProvider(new BouncyCastleProvider());
    }

    public Client(URL url, ECPublicKey serverPublicKey) {
        this.url = url;
        this.serverPublicKey = serverPublicKey;
    }

    @Override
    public void register(ECPrivateKey privateKey, ECPublicKey publicKey, int amount) throws JsonProcessingException, KeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, UnsupportedEncodingException, SignatureException {

        String b64PublicKey = Utils.publicKeyToBase64(publicKey);
        String nonce = Utils.randomNonce();

        Map<String,Object> payload = new HashMap<>();
        payload.put("key", b64PublicKey);
        payload.put("amount", amount);
        String payloadJson = new ObjectMapper().writeValueAsString(payload);

        String hashInput = nonce + b64PublicKey + amount; //Not against surreptitious forwarding
        String signature = Utils.generateSignature(hashInput, privateKey);

        HttpRequest request = HttpRequest.post(url.toString() + "/register")
                .header("SIGNATURE", signature)
                .header("NONCE", nonce)
                .send(payloadJson);

        if(request.code() != 200) {
            throw new RuntimeException("Something went wrong");
        }

        String responseSignature = request.header("SIGNATURE");
        String responseNonce = request.header("NONCE");

        boolean result = Utils.checkSignature(responseSignature, responseNonce, Utils.publicKeyToBase64(serverPublicKey));
        if(!result) {
            throw new RuntimeException("Received invalid signature");
        }
        System.out.println("NONCE: "+nonce);
        System.out.println("ResponseNOnce: "+responseNonce);
        if(!responseNonce.equals(nonce)) {
            throw new RuntimeException("Nonce does not match");
        }
    }

    @Override
    public void sendAmount(ECPrivateKey privateKey, ECPublicKey source, PublicKey destination, int amount) throws KeyException, JsonProcessingException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, SignatureException {
        String b64SourcePublicKey = Utils.publicKeyToBase64(source);
        String b64DestinationPublicKey = Utils.publicKeyToBase64(source);
        String nonce = Utils.randomNonce();

        Map<String, Object> payload = new HashMap<>();
        payload.put("source", b64SourcePublicKey);
        payload.put("destination", b64DestinationPublicKey);
        payload.put("amount", amount);
        String payloadJson = new ObjectMapper().writeValueAsString(payload);

        String hashInput = nonce + b64SourcePublicKey + b64DestinationPublicKey + amount; //Not against surreptitious forwarding
        String signature = Utils.generateSignature(hashInput, privateKey);

        HttpRequest request = HttpRequest.post(url.toString() + "/sendAmount")
                .header("SIGNATURE", signature)
                .header("NONCE", nonce)
                .send(payloadJson);

        if(request.code() != 200) {
            throw new RuntimeException("Something went wrong");
        }

        String responseSignature = request.header("SIGNATURE");
        String responseNonce = request.header("NONCE");

        boolean result = Utils.checkSignature(responseSignature, responseNonce, Utils.publicKeyToBase64(serverPublicKey));
        if(!result) {
            throw new RuntimeException("Received invalid signature");
        }

        if(!responseNonce.equals(nonce)) {
            throw new RuntimeException("Nonce does not match");
        }
    }

    @Override
    public int checkAccount(ECPrivateKey privateKey, ECPublicKey key) {
        return 0;
    }

    @Override
    public void receiveAmount(ECPrivateKey privateKey, ECPublicKey publicKey) throws KeyException, JsonProcessingException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
        String b64PublicKey = Utils.publicKeyToBase64(publicKey);
        String nonce = Utils.randomNonce();

        Map<String,Object> payload = new HashMap<>();
        payload.put("key", b64PublicKey);
        String payloadJson = new ObjectMapper().writeValueAsString(payload);

        String hashInput = nonce + b64PublicKey; //Not against surreptitious forwarding
        String signature = Utils.generateSignature(hashInput, privateKey);

        HttpRequest request = HttpRequest.post(url.toString() + "/register")
                .header("SIGNATURE", signature)
                .header("NONCE", nonce)
                .send(payloadJson);

        if(request.code() != 200) {
            throw new RuntimeException("Something went wrong");
        }

        String responseSignature = request.header("SIGNATURE");
        String responseNonce = request.header("NONCE");

        boolean result = Utils.checkSignature(responseSignature, responseNonce, Utils.publicKeyToBase64(serverPublicKey));
        if(!result) {
            throw new RuntimeException("Received invalid signature");
        }
        System.out.println("NONCE: " + nonce);
        System.out.println("ResponseNOnce: " + responseNonce);
        if(!responseNonce.equals(nonce)) {
            throw new RuntimeException("Nonce does not match");
        }
    }

    @Override
    public void audit(ECPrivateKey privateKey, ECPublicKey key) {

    }
}
