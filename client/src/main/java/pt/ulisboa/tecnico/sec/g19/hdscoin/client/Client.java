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
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.SignatureException;

import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

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
    public void register(ECPublicKey publicKey, ECPrivateKey privateKey, int amount) throws RegisterException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64(publicKey);
            Serialization.RegisterRequest request = new Serialization.RegisterRequest();
            request.initialTransaction = new Serialization.Transaction();
            request.initialTransaction.source = b64PublicKey;
            request.initialTransaction.target = b64PublicKey;
            request.initialTransaction.amount = amount;
            request.initialTransaction.isSend = false;
            request.initialTransaction.previousSignature = "";
            request.initialTransaction.nonce = Utils.randomNonce();
            request.initialTransaction.signature = Utils.generateSignature(request.initialTransaction.getSignable(), privateKey);
            // log
            System.out.println();
            System.out.println("---------------------");
            System.out.println("---Sending Request---");
            System.out.println("Base 64 Public Key: " + b64PublicKey);
            System.out.println("Amount: " + amount);
            System.out.println("Nonce: " + request.initialTransaction.nonce);
            System.out.println("---------------------");
            System.out.println();

            // http post request
            Serialization.Response response = sendPostRequest(url.toString() + "/register", privateKey, request,
                    Serialization.Response.class);

            if (response.statusCode == 200) {
                System.out.println();
                System.out.println("---------------------------------");
                System.out.println("---Registration was successful---");
                System.out.println("---------------------------------");
                System.out.println();

            } else {
                switch (response.status) {
                    case ERROR_INVALID_KEY:
                        throw new InvalidKeyException("The public key provided is not valid.");
                    case ERROR_INVALID_AMOUNT:
                        throw new InvalidAmountException("The amount provided is invalid.", amount);
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException("The public key is already associated with a ledger.");
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException("Error on the server side.");
                }
            }

        } catch (HttpRequest.HttpRequestException | IOException | KeyException | SignatureException |
                InvalidServerResponseException | InvalidClientSignatureException | InvalidKeyException |
                InvalidLedgerException | InvalidAmountException | ServerErrorException e) {
            throw new RegisterException("Failed to register the public key provided. " + e, e);
        }
    }

    @Override
    public void sendAmount(ECPublicKey sourcePublicKey, ECPublicKey targetPublicKey, int amount,
                           ECPrivateKey sourcePrivateKey, String previousSignature) throws SendAmountException {
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
                System.out.println();
                System.out.println("--------------------------------");
                System.out.println("---Transaction was successful---");
                System.out.println("--Waiting for target to accept--");
                System.out.println("--------------------------------");
                System.out.println();

            } else {
                switch (response.status) {
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException("Error on the server side.");
                }
            }
        } catch (HttpRequest.HttpRequestException | IOException | KeyException | SignatureException |
                InvalidServerResponseException | InvalidClientSignatureException | ServerErrorException e) {
            throw new SendAmountException("Failed to create a transaction. " + e);
        }
    }

    @Override
    public int checkAccount(ECPublicKey publicKey) throws CheckAccountException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64(publicKey);
            String requestPath = url.toString() +
                    "/checkAccount/" + URLEncoder.encode(b64PublicKey, "UTF-8");

            Serialization.CheckAccountResponse response = sendGetRequest(requestPath,
                    Serialization.CheckAccountResponse.class);

            System.out.println("response.statusCode: " + response.statusCode);
            System.out.println("response.status: " + response.status);

            if (response.statusCode == 200) {
                System.out.println("\n");
                System.out.println("----------------------------------");
                System.out.println("---Check account was successful---");
                System.out.println();
                System.out.println("Balance: " + response.balance);
                System.out.println("Pending Transactions:");
                System.out.println(response.pendingTransactions.toString());
                System.out.println("----------------------------------");
            } else {
                switch (response.status) {
                    case ERROR_INVALID_KEY:
                        throw new InvalidKeyException("The public key provided is not valid.");
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException("The public key provided isn't associated with any ledger.");
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException("Error on the server side.");
                }
            }

            // todo: return an object with the balance and the transactions
            return 0;
        } catch (InvalidKeyException | InvalidLedgerException | ServerErrorException | IOException | KeyException |
                InvalidServerResponseException | SignatureException e) {
            throw new CheckAccountException("Failed to check the account of the public key provided. " + e);
        }
    }

    @Override
    public void receiveAmount(ECPublicKey publicKey, ECPrivateKey privateKey, String transactionSignature) throws ReceiveAmountException {
        // todo: handle
    }

    @Override
    public List<Serialization.Transaction> audit(ECPublicKey publicKey) throws AuditException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64(publicKey);
            String requestPath = url.toString() +
                    "/audit/" + URLEncoder.encode(b64PublicKey, "UTF-8");

            Serialization.AuditResponse response = sendGetRequest(requestPath,
                    Serialization.AuditResponse.class);

            System.out.println("response.statusCode: " + response.statusCode);
            System.out.println("response.status: " + response.status);

            if (response.statusCode == 200) {
                // check transaction chain
                // transactions come ordered from the oldest to the newest
                String prevHash = null;
                for (Serialization.Transaction tx : response.transactions) {
                    System.out.println("Checking signature: " + tx.signature);
                    if (!Utils.checkSignature(tx.signature, tx.getSignable(), publicKey)) {
                        throw new AuditException("Error checking signature of transaction");
                    }
                    // now we know tx.signature is correct... but is it signing the right prevHash?
                    if (prevHash != null && !prevHash.equals(tx.signature)) {
                        throw new AuditException("Transaction chain is broken: the previous signature contained in " +
                                "one transaction does not match the signature of the transaction that precedes it");
                    }
                    prevHash = tx.signature;
                }

                System.out.println("\n");
                System.out.println("----------------------------------");
                System.out.println("-------Audit was successful-------");
                System.out.println("----------------------------------");
                return response.transactions;
            }
            switch (response.status) {
                case ERROR_INVALID_KEY:
                    throw new InvalidKeyException("The public key provided is not valid.");
                case ERROR_INVALID_LEDGER:
                    throw new InvalidLedgerException("The public key provided isn't associated with any ledger.");
                case ERROR_SERVER_ERROR:
                default:
                    throw new ServerErrorException("Error on the server side.");
            }
        } catch (InvalidKeyException | InvalidLedgerException | ServerErrorException | IOException | KeyException |
                InvalidServerResponseException | SignatureException e) {
            throw new AuditException("Failed to audit the account of the public key provided. " + e);
        }
    }

    private <T> T sendPostRequest(String url, ECPrivateKey privateKey, Object payload, Class<T> responseValueType) throws HttpRequest.HttpRequestException, IOException, SignatureException, InvalidServerResponseException, InvalidClientSignatureException {
        String payloadJson = Serialization.serialize(payload);
        String nonce = ((NonceContainer) payload).getNonce();

        HttpRequest request = HttpRequest
                .post(url);
        //.header(Serialization.NONCE_HEADER_NAME, nonce);

        if (payload instanceof Signable) {
            String toSign = ((Signable) payload).getSignable();
            // added the nonce to the signable message on the request
            request = request.header(Serialization.SIGNATURE_HEADER_NAME, Utils.generateSignature(toSign, privateKey));
        }

        request.send(payloadJson);

        int responseCode = request.code();

        String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
        T response = Serialization.parse(request.body(), responseValueType);

        if (!(response instanceof Signable && response instanceof NonceContainer)) {
            throw new InvalidServerResponseException("Response isn't signable or doesn't contain a nonce.\n " +
                    "Impossible to check if the sender was really the server.");
        }

        boolean result = Utils.checkSignature(responseSignature, ((Signable) response).getSignable(), serverPublicKey);
        if (!result) {
            throw new InvalidServerResponseException("Server signatures do not match.");
        }

        String responseNonce = ((NonceContainer) response).getNonce();
        System.out.println("Client NONCE: " + nonce);
        System.out.println("Server NONCE: " + responseNonce);
        System.out.println("SIGN : " + responseSignature);
        if (!responseNonce.equals(nonce)) {
            throw new InvalidServerResponseException("The nonce received by the server do not match the one " +
                    "the client sent previously.");
        }

        if (responseCode != 200) {
            if (((Serialization.Response) response).status.equals(ERROR_NO_SIGNATURE_MATCH)) {
                throw new InvalidClientSignatureException("The message was reject by the server, because the " +
                        "client signature didn't match.");
            }
        }

        return response;
    }

    private <T> T sendGetRequest(String url, Class<T> responsValueType) throws HttpRequest.HttpRequestException, IOException, InvalidServerResponseException, SignatureException {
        String nonce = Utils.randomNonce();
        HttpRequest request = HttpRequest
                .get(url)
                .header(Serialization.NONCE_HEADER_NAME, nonce);

        int responseCode = request.code();

        String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
        T response = Serialization.parse(request.body(), responsValueType);

        if (!(response instanceof Signable && response instanceof NonceContainer)) {
            throw new InvalidServerResponseException("Response isn't signable or doesn't contain a nonce.\n " +
                    "Impossible to check if the sender was really the server.");
        }

        boolean result = Utils.checkSignature(responseSignature, ((Signable) response).getSignable(), serverPublicKey);
        if (!result) {
            throw new InvalidServerResponseException("Server signatures do not match.");
        }

        String responseNonce = ((NonceContainer) response).getNonce();

        System.out.println("Client NONCE: " + nonce);
        System.out.println("Server NONCE: " + responseNonce);
        if (!responseNonce.equals(nonce)) {
            throw new InvalidServerResponseException("The nonce received by the server do not match the one " +
                    "the client sent previously.");
        }

        if (responseCode != 200) {
            // todo: handle
        }

        return response;
    }

}
