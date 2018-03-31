package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.kevinsawicki.http.HttpRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.NonceContainer;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Signable;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

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
    public void register(ECPrivateKey privateKey, ECPublicKey publicKey, double amount) throws IOException, KeyException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, SignatureException {
        String b64PublicKey = Serialization.publicKeyToBase64(publicKey);
        System.out.println("BASE 64 PUBLIC KEY: " + b64PublicKey);
        Serialization.RegisterRequest request = new Serialization.RegisterRequest();
        request.amount = amount;
        request.key = b64PublicKey;

        sendPostRequest(url.toString() + "/register", privateKey, request, Serialization.Response.class);
        // TODO we must check that the response was successful and maybe implement retry logic if not
    }

    @Override
    public void sendAmount(ECPrivateKey privateKey, ECPublicKey source, ECPublicKey destination, double amount) throws KeyException, IOException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, SignatureException {
        String b64SourcePublicKey = Serialization.publicKeyToBase64(source);
        String b64DestinationPublicKey = Serialization.publicKeyToBase64(destination);

        Serialization.SendAmountRequest request = new Serialization.SendAmountRequest();
        request.source = b64SourcePublicKey;
        request.destination = b64DestinationPublicKey;
        request.amount = amount;
        request.previousSignature = "TODO"; // TODO we must first do a request to obtain our last tx so we can get its signature

        sendPostRequest(url.toString() + "/sendAmount", privateKey, request, Serialization.Response.class);
        // TODO we must check that the response was successful and maybe implement retry logic if not
    }

    @Override
    public int checkAccount(ECPrivateKey privateKey, ECPublicKey key) {
        return 0;
    }

    @Override
    public void receiveAmount(ECPrivateKey privateKey, String sendTxSignature) throws KeyException, IOException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
        // TODO do request to obtain the details of the send tx we want to accept
        // then build a ReceiveAmountRequest with the necessary fields
    }

    @Override
    public void audit(ECPrivateKey privateKey, ECPublicKey key) {

    }

    // TODO: better exceptions
    private <T> T sendPostRequest(String url, ECPrivateKey privateKey, Object payload, Class<T> responseValueType) throws IOException, KeyException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, SignatureException {
        String payloadJson = Serialization.serialize(payload);
        String nonce = Utils.randomNonce();

        HttpRequest request = HttpRequest.post(url);

        if (payload instanceof Signable) {
            String toSign = ((Signable) payload).getSignable();
            request = request.header("SIGNATURE", Utils.generateSignature(toSign, privateKey));
        }

        request = request.header("NONCE", nonce)
                .send(payloadJson);

        if (request.code() != 200) {
            // TODO: better exceptions
            throw new RuntimeException("Something went wrong");
        }

        String responseSignature = request.header("SIGNATURE");
        T response = Serialization.parse(request.body(), responseValueType);

        if(!(response instanceof Signable && response instanceof NonceContainer)) {
            // TODO: better exceptions
            // not a valid response from the "server"
            throw new RuntimeException("Response isn't signable or doesn't contain a nonce");
        }

        boolean result = Utils.checkSignature(responseSignature, ((Signable) response).getSignable(), serverPublicKey);
        if (!result) {
            // TODO: better exceptions
            throw new RuntimeException("Received invalid signature");
        }

        String responseNonce = ((NonceContainer) response).getNonce();

        System.out.println("NONCE: " + nonce);
        System.out.println("ResponseNOnce: " + responseNonce);
        if (!responseNonce.equals(nonce)) {
            // TODO: better exceptions
            throw new RuntimeException("Nonce does not match");
        }

        return response;
    }
}
