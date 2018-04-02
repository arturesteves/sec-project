package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import com.github.kevinsawicki.http.HttpRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.NonceContainer;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Signable;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidKeyException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
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
    public void register(ECPublicKey publicKey, ECPrivateKey privateKey, double amount) throws CantRegisterException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64(publicKey);
            Serialization.RegisterRequest request = new Serialization.RegisterRequest();
            request.amount = amount;
            request.key = b64PublicKey;
            // log
            System.out.println ("---------------------");
            System.out.println ("---Sending Request---");
            System.out.println ("Base 64 Public Key: " + b64PublicKey);
            System.out.println ("Amount: " + amount);
            System.out.println ("---------------------");
            // http post request
            Serialization.Response response = sendPostRequest(url.toString() + "/register", privateKey, request,
                    Serialization.Response.class);

            if (response.statusCode == 200) {
                System.out.println("\n");
                System.out.println ("---------------------------------");
                System.out.println ("---Registration was successful---");
                System.out.println ();
                System.out.println ("---------------------------------");
            } else {
                switch (response.status) {
                    case ERROR_INVALID_KEY:
                        throw new InvalidKeyException ("The public key provided is not valid.");
                    case ERROR_INVALID_AMOUNT:
                        throw new InvalidAmountException ("The amount provided is invalid.", amount);
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException ("The public key provided isn't associated with any ledger.");
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException ("Error on the server side.");
                }
            }
        } catch (HttpRequest.HttpRequestException | IOException | KeyException | CantGenerateSignatureException |
                    InvalidServerResponseException | InvalidClientSignatureException | InvalidKeyException |
                    InvalidLedgerException | InvalidAmountException | ServerErrorException e) {
            throw new CantRegisterException ("Failed to register the public key provided. " + e);
        }
    }

    @Override
    public void sendAmount(ECPublicKey sourcePublicKey, ECPublicKey targetPublicKey, double amount,
                           ECPrivateKey sourcePrivateKey, String previousSignature) throws CantSendAccountException {
        try {
            String b64SourcePublicKey = Serialization.publicKeyToBase64(sourcePublicKey);
            String b64DestinationPublicKey = Serialization.publicKeyToBase64(targetPublicKey);

            Serialization.SendAmountRequest request = new Serialization.SendAmountRequest();
            request.source = b64SourcePublicKey;
            request.target = b64DestinationPublicKey;
            request.amount = amount;
            request.previousSignature = previousSignature;

            Serialization.Response response = sendPostRequest(url.toString() + "/sendAmount", sourcePrivateKey,
                    request, Serialization.Response.class);

            if (response.statusCode == 200) {
                System.out.println ("\n");
                System.out.println ("--------------------------------");
                System.out.println ("---Transaction was successful---");
                System.out.println ("--Waiting for target to accept--");
                System.out.println ();
                System.out.println ("--------------------------------");
            } else {
                switch (response.status) {
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException ("Error on the server side.");
                }
            }
        } catch (HttpRequest.HttpRequestException | IOException | KeyException | CantGenerateSignatureException |
                InvalidServerResponseException | InvalidClientSignatureException | ServerErrorException e) {
            throw new CantSendAccountException ("Failed to create a transaction. " + e);
        }
    }

    @Override
    public int checkAccount(ECPublicKey publicKey) throws CantCheckAccountException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64 (publicKey);
            String requestPath = url.toString () +
                                    "/checkAccount?publickey=" + URLEncoder.encode (b64PublicKey, "UTF-8");

            Serialization.CheckAccountResponse response = sendGetRequest(requestPath,
                                                                Serialization.CheckAccountResponse.class);

            System.out.println("response.statusCode: " + response.statusCode);
            System.out.println("response.status: " + response.status);

            if (response.statusCode == 200) {
                System.out.println ("\n");
                System.out.println ("----------------------------------");
                System.out.println ("---Check account was successful---");
                System.out.println ();
                System.out.println ("Balance: " + response.balance);
                System.out.println ("Pending Transactions:");
                System.out.println (response.pendingTransactions.toString ());
                System.out.println ("----------------------------------");
            } else {
                switch (response.status) {
                    case ERROR_INVALID_KEY:
                        throw new InvalidKeyException ("The public key provided is not valid.");
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException ("The public key provided isn't associated with any ledger.");
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException ("Error on the server side.");
                }
            }

            // todo: return an object with the balance and the transactions
            return 0;
        } catch (InvalidKeyException | InvalidLedgerException | ServerErrorException | IOException | KeyException |
                    InvalidServerResponseException | CantGenerateSignatureException e) {
            throw new CantCheckAccountException ("Failed to check the account of the public key provided. " + e);
        }
    }

    @Override
    public void receiveAmount(ECPrivateKey privateKey, String sendTxSignature) throws KeyException, IOException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
        // TODO do request to obtain the details of the send tx we want to accept
        // then build a ReceiveAmountRequest with the necessary fields
    }

    @Override
    public void audit(ECPrivateKey privateKey, ECPublicKey key) {

    }

    private <T> T sendPostRequest(String url, ECPrivateKey privateKey, Object payload, Class<T> responseValueType) throws HttpRequest.HttpRequestException, IOException, CantGenerateSignatureException, InvalidServerResponseException, InvalidClientSignatureException {
        String payloadJson = Serialization.serialize(payload);
        String nonce = Utils.randomNonce();

        HttpRequest request = HttpRequest.post(url);

        if (payload instanceof Signable) {
            String toSign = ((Signable) payload).getSignable();
            request = request.header("SIGNATURE", Utils.generateSignature(toSign, privateKey));
        }

        request = request.header("NONCE", nonce)
                .send(payloadJson);

        int responseCode = request.code ();

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

        System.out.println("Client NONCE: " + nonce);
        System.out.println("Server NONCE: " + responseNonce);
        if (!responseNonce.equals(nonce)) {
            throw new InvalidServerResponseException ("The nonce received by the server do not match the one " +
                    "the client sent previously.");
        }

        if ( responseCode != 200 ) {
            if ( ((Serialization.Response) response).status.equals (ERROR_NO_SIGNATURE_MATCH)) {
                throw new InvalidClientSignatureException ("The message was reject by the server, because the " +
                            "client signature didn't match.");
            }
        }

        return response;
    }

    private <T> T sendGetRequest (String url, Class<T> responsValueType) throws HttpRequest.HttpRequestException, IOException, InvalidServerResponseException, CantGenerateSignatureException {
        String nonce = Utils.randomNonce();
        HttpRequest request = HttpRequest.get (url);
        request = request.header("NONCE", nonce);

        int responseCode = request.code ();

        String responseSignature = request.header("SIGNATURE");
        T response = Serialization.parse (request.body (), responsValueType);

        if(!(response instanceof Signable && response instanceof NonceContainer)) {
            throw new InvalidServerResponseException ("Response isn't signable or doesn't contain a nonce.\n " +
                    "Impossible to check if the sender was really the server.");
        }

        boolean result = Utils.checkSignature(responseSignature, ((Signable) response).getSignable(), serverPublicKey);
        if (!result) {
            throw new InvalidServerResponseException ("Server signatures do not match.");
        }

        String responseNonce = ((NonceContainer) response).getNonce();

        System.out.println("Client NONCE: " + nonce);
        System.out.println("Server NONCE: " + responseNonce);
        if (!responseNonce.equals(nonce)) {
            throw new InvalidServerResponseException ("The nonce received by the server do not match the one " +
                    "the client sent previously.");
        }

        if (responseCode != 200) {
            // todo: handle
        }

        return response;
    }

}
