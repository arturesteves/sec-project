package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import com.github.kevinsawicki.http.HttpRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantRegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.InvalidClientSignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.InvalidServerResponseException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.ServerErrorException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.NonceContainer;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Signable;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidKeyException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.StatusMessage.ERROR_NO_SIGNATURE_MATCH;

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
    public void register(ECPrivateKey privateKey, ECPublicKey publicKey, double amount) throws CantRegisterException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64(publicKey);
            Serialization.RegisterRequest request = new Serialization.RegisterRequest();
            request.amount = amount;
            request.key = b64PublicKey;
            // log
            System.out.println ("---Sending Request---");
            System.out.println("Base 64 Public Key: " + b64PublicKey);
            System.out.println("Amount: " + amount);
            // http post request
            Serialization.Response response = sendPostRequest(url.toString() + "/register", privateKey, request, Serialization.Response.class);

            if (response.statusCode == 200) {
                System.out.println("---Registration was successful---");
            } else {
                checkErrors(amount, response);
            }
        } catch (IOException | KeyException | CantGenerateSignatureException | InvalidServerResponseException
                    | InvalidClientSignatureException | InvalidKeyException | InvalidLedgerException
                    | InvalidAmountException | ServerErrorException e) {
            throw new CantRegisterException ("Couldn't register the public key provided. " + e.getMessage (), e);
        }
    }

    private void checkErrors(double amount, Serialization.Response response) throws InvalidKeyException, InvalidAmountException, InvalidLedgerException, ServerErrorException {
        switch (response.status) {
            case ERROR_INVALID_KEY:
                throw new InvalidKeyException ("The public key provided is not valid.");
            case ERROR_INVALID_AMOUNT:
                throw new InvalidAmountException ("The amount provided is invalid.", amount);
            case ERROR_INVALID_LEDGER:
                throw new InvalidLedgerException ("The public key provided is not valid.");
            case ERROR_SERVER_ERROR:
                throw new ServerErrorException ("Error on the server side.");
        }
    }

    @Override
    public void sendAmount(ECPrivateKey privateKey, ECPublicKey source, ECPublicKey destination, double amount) throws KeyException, IOException, CantGenerateSignatureException, InvalidServerResponseException, InvalidClientSignatureException {
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
    private <T> T sendPostRequest(String url, ECPrivateKey privateKey, Object payload, Class<T> responseValueType) throws IOException, CantGenerateSignatureException, InvalidServerResponseException, InvalidClientSignatureException {
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
            if (request.body ().equals(ERROR_NO_SIGNATURE_MATCH.toString())) {
                throw new InvalidClientSignatureException ("The message was reject by the server, because the " +
                        "client signature didn't match.");
            }else {
                return Serialization.parse(request.body (), responseValueType);
            }
        }

        String responseSignature = request.header("SIGNATURE");
        T response = Serialization.parse(request.body(), responseValueType);

        if(!(response instanceof Signable && response instanceof NonceContainer)) {
            throw new InvalidServerResponseException ("Response isn't signable or doesn't contain a nonce.\n " +
                    "Impossible to check if the sender was really the server.");
        }

        boolean result = Utils.checkSignature(responseSignature, ((Signable) response).getSignable(), serverPublicKey);
        if (!result) {
            throw new InvalidServerResponseException ("Server signatures do not match.");
        }

        String responseNonce = ((NonceContainer) response).getNonce();

        System.out.println("NONCE: " + nonce);
        System.out.println("ResponseNOnce: " + responseNonce);
        if (!responseNonce.equals(nonce)) {
            throw new InvalidServerResponseException ("The nonce received by the server do not match the one " +
                    "the client sent previously.");
        }

        // no error detected
        return response;
    }
}
