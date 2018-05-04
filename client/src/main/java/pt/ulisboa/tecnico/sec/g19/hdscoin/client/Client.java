package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import com.github.kevinsawicki.http.HttpRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidKeyException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.SignatureException;

import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.SERVER_PREFIX;
import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.StatusMessage.ERROR_NO_SIGNATURE_MATCH;


public class Client implements IClient {


    static {
        Security.addProvider (new BouncyCastleProvider ());
    }

    private List<ServerInfo> servers;
    private List<ServerInfo> ackList;
    //private List<Ledger> readList;
    private int numberOfMaxFaults;

    public Client (URL url, int numberOfServers, String keyStoreFilepath) {
        this.servers = getServersInfoFromKeyStore (url, numberOfServers, keyStoreFilepath);
        this.numberOfMaxFaults = Utils.numberOfFaultsSupported (numberOfServers);
        this.ackList = new ArrayList<> ();
    }

    private List<ServerInfo> getServersInfoFromKeyStore (URL url, int numberOfServers, String keyStoreFilepath) {
        List<ServerInfo> serverInfos = new ArrayList<> ();
        try {
            KeyStore keyStore = Utils.initKeyStore (keyStoreFilepath);
            for (int i = 0; i < numberOfServers; i++) {
                ServerInfo serverInfo = new ServerInfo ();
                serverInfo.serverUrl = new URL (url.getProtocol () + "://" + url.getHost () + ":" + (url.getPort () + i));
                serverInfo.publicKeyBase64 =
                        Serialization.publicKeyToBase64 (Utils.loadPublicKeyFromKeyStore (keyStore, SERVER_PREFIX + (i + 1)));
                serverInfos.add (serverInfo);
            }
            return serverInfos;
        } catch(CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyException e) {
            e.printStackTrace ();
            throw new RuntimeException (e);
        }
    }

    @Override public void register (ECPublicKey publicKey, ECPrivateKey privateKey, int amount)
            throws RegisterException, KeyException {
        for (ServerInfo server : this.servers) {
            System.out.println ("server: " + server);
            System.out.println ("publicKey: " + Serialization.publicKeyToBase64 (publicKey));
            System.out.println ("privateKey: " + Serialization.privateKeyToBase64 (privateKey));
            System.out.println ("amount: " + amount);
            register (server, publicKey, privateKey, amount);
        }
    }

    @Override
    public void sendAmount (ECPublicKey sourcePublicKey, ECPublicKey targetPublicKey, int amount,
                            ECPrivateKey sourcePrivateKey, String previousSignature) throws SendAmountException {
        for (ServerInfo server : this.servers) {
            sendAmount (server, sourcePublicKey, targetPublicKey, amount, sourcePrivateKey, previousSignature);
        }
    }

    @Override public CheckAccountResult checkAccount (ECPublicKey publicKey) throws CheckAccountException {
        CheckAccountResult checkAccountResult = null;
        for (ServerInfo server : this.servers) {
            checkAccountResult = checkAccount (server, publicKey);
        }
        return checkAccountResult;
    }

    @Override
    public void receiveAmount (ECPublicKey sourcePublicKey, String targetPublicKey, int amount,
                               ECPrivateKey sourcePrivateKey, String previousSignature, String incomingSignature)
            throws ReceiveAmountException {
        for (ServerInfo server : this.servers) {
            receiveAmount (server, sourcePublicKey, targetPublicKey, amount, sourcePrivateKey, previousSignature,
                    incomingSignature);
        }
    }

    @Override public List<Serialization.Transaction> audit (ECPublicKey publicKey) throws AuditException {
        List<Serialization.Transaction> transactions = null;
        for (ServerInfo server : this.servers) {
            transactions = audit (server, publicKey);
        }
        return transactions;
    }

    private void register (ServerInfo server, ECPublicKey publicKey, ECPrivateKey privateKey, int amount)
            throws RegisterException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64 (publicKey);
            Serialization.RegisterRequest request = new Serialization.RegisterRequest ();
            request.initialTransaction = new Serialization.Transaction ();
            request.initialTransaction.source = b64PublicKey;
            request.initialTransaction.target = b64PublicKey;
            request.initialTransaction.amount = amount;
            request.initialTransaction.isSend = false;
            request.initialTransaction.previousSignature = "";
            request.initialTransaction.nonce = Utils.randomNonce ();
            request.initialTransaction.signature =
                    Utils.generateSignature (request.initialTransaction.getSignable (), privateKey);
            // log
            System.out.println ();
            System.out.println ("---------------------");
            System.out.println ("---Sending Request---");
            System.out.println ("Base 64 Public Key: " + b64PublicKey);
            System.out.println ("Amount: " + amount);
            System.out.println ("Nonce: " + request.initialTransaction.nonce);
            System.out.println ("---------------------");
            System.out.println ();

            // http post request
            Serialization.Response response = sendPostRequest (Serialization.base64toPublicKey (server.publicKeyBase64),
                    server.serverUrl.toString () + "/register", privateKey, request, Serialization.Response.class);

            if (response.statusCode == 200) {
                System.out.println ();
                System.out.println ("---------------------------------");
                System.out.println ("---Registration was successful---");
                System.out.println ("---------------------------------");
                System.out.println ();

            } else {
                switch (response.status) {
                    case ERROR_INVALID_KEY:
                        throw new InvalidKeyException ("The public key provided is not valid.");
                    case ERROR_INVALID_AMOUNT:
                        throw new InvalidAmountException ("The amount provided is invalid.", amount);
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException ("The public key is already associated with a ledger.");
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException ("Error on the server side.");
                }
            }

        } catch (HttpRequest.HttpRequestException | IOException | KeyException | SignatureException | InvalidServerResponseException | InvalidClientSignatureException | InvalidKeyException | InvalidLedgerException | InvalidAmountException | ServerErrorException e) {
            throw new RegisterException ("Failed to register the public key provided. " + e, e);
        }
    }

    private void sendAmount (ServerInfo server, ECPublicKey sourcePublicKey, ECPublicKey targetPublicKey, int amount,
                             ECPrivateKey sourcePrivateKey, String previousSignature) throws SendAmountException {
        try {
            String b64SourcePublicKey = Serialization.publicKeyToBase64 (sourcePublicKey);
            String b64DestinationPublicKey = Serialization.publicKeyToBase64 (targetPublicKey);

            Serialization.SendAmountRequest request = new Serialization.SendAmountRequest ();
            request.source = b64SourcePublicKey;
            request.target = b64DestinationPublicKey;
            request.amount = amount;
            request.nonce = Utils.randomNonce ();
            request.previousSignature = previousSignature;
            request.signature = Utils.generateSignature (request.getSignable (), sourcePrivateKey);

            Serialization.Response response = sendPostRequest (Serialization.base64toPublicKey (server.publicKeyBase64),
                    server.serverUrl.toString () + "/sendAmount", sourcePrivateKey, request,
                    Serialization.Response.class);

            if (response.statusCode == 200) {
                System.out.println ();
                System.out.println ("--------------------------------");
                System.out.println ("---Transaction was successful---");
                System.out.println ("--Waiting for target to accept--");
                System.out.println ("--------------------------------");
                System.out.println ();

            } else {
                switch (response.status) {
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException ("Source or destination is invalid");
                    case ERROR_INVALID_KEY:
                        throw new InvalidLedgerException ("One of the keys provided is invalid");
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException ("Error on the server side.");
                }
            }
        } catch (HttpRequest.HttpRequestException | IOException | KeyException | SignatureException | InvalidServerResponseException | InvalidClientSignatureException | ServerErrorException | InvalidLedgerException e) {
            throw new SendAmountException ("Failed to create a transaction. " + e);
        }
    }

    private CheckAccountResult checkAccount (ServerInfo server, ECPublicKey publicKey) throws CheckAccountException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64 (publicKey);
            String requestPath =
                    server.serverUrl.toString () + "/checkAccount/" + URLEncoder.encode (b64PublicKey, "UTF-8");

            Serialization.CheckAccountResponse response =
                    sendGetRequest (Serialization.base64toPublicKey (server.publicKeyBase64), requestPath,
                            Serialization.CheckAccountResponse.class);

            System.out.println ("response.statusCode: " + response.statusCode);
            System.out.println ("response.status: " + response.status);

            if (response.statusCode == 200) {
                System.out.println ("\n");
                System.out.println ("----------------------------------");
                System.out.println ("---Check account was successful---");
                System.out.println ("----------------------------------");
                return new CheckAccountResult (response.balance, response.pendingTransactions);
            } else {
                switch (response.status) {
                    case ERROR_INVALID_KEY:
                        throw new InvalidKeyException ("The public key provided is not valid.");
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException ("The public key provided isn't associated with any ledger.");
                    case ERROR_SERVER_ERROR:
                    default:
                        throw new ServerErrorException ("Error on the server side.");
                }
            }
        } catch (InvalidKeyException | InvalidLedgerException | ServerErrorException | IOException | KeyException | InvalidServerResponseException | SignatureException e) {
            throw new CheckAccountException ("Failed to check the account of the public key provided. " + e);
        }
    }

    private void receiveAmount (ServerInfo server, ECPublicKey sourcePublicKey, String targetPublicKey, int amount,
                                ECPrivateKey sourcePrivateKey, String previousSignature, String incomingSignature)
            throws ReceiveAmountException {
        try {
            String b64SourcePublicKey = Serialization.publicKeyToBase64 (sourcePublicKey);
            String b64DestinationPublicKey = targetPublicKey;

            Serialization.ReceiveAmountRequest request = new Serialization.ReceiveAmountRequest ();
            request.transaction = new Serialization.Transaction ();
            request.transaction.source = b64SourcePublicKey;
            request.transaction.target = b64DestinationPublicKey;
            request.transaction.amount = amount;
            request.transaction.nonce = Utils.randomNonce ();
            request.transaction.previousSignature = previousSignature;
            // signature for just the transaction:
            request.transaction.signature =
                    Utils.generateSignature (request.transaction.getSignable (), sourcePrivateKey);
            request.pendingTransactionHash = incomingSignature;
            // signature for the whole request (including transaction):

            Serialization.Response response = sendPostRequest (Serialization.base64toPublicKey (server.publicKeyBase64),
                    server.serverUrl.toString () + "/receiveAmount", sourcePrivateKey, request,
                    Serialization.Response.class);

            if (response.statusCode == 200) {
                System.out.println ();
                System.out.println ("---------------------------------------");
                System.out.println ("---Transaction accepted successfully---");
                System.out.println ("---------------------------------------");
                System.out.println ();

            } else {
                switch (response.status) {
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException ("Source or destination is invalid");
                    case ERROR_INVALID_KEY:
                        throw new InvalidLedgerException ("One of the keys provided is invalid");
                    case ERROR_INVALID_VALUE:
                        throw new InvalidLedgerException ("One of the values provided is invalid");
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException ("Error on the server side.");
                }
            }
        } catch (HttpRequest.HttpRequestException | IOException | KeyException | SignatureException | InvalidServerResponseException | InvalidClientSignatureException | ServerErrorException | InvalidLedgerException e) {
            throw new ReceiveAmountException ("Failed to create a receiving transaction. " + e);
        }
    }

    private List<Serialization.Transaction> audit (ServerInfo server, ECPublicKey publicKey) throws AuditException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64 (publicKey);
            String requestPath = server.serverUrl.toString () + "/audit/" + URLEncoder.encode (b64PublicKey, "UTF-8");

            Serialization.AuditResponse response =
                    sendGetRequest (Serialization.base64toPublicKey (server.publicKeyBase64), requestPath,
                            Serialization.AuditResponse.class);

            System.out.println ("response.statusCode: " + response.statusCode);
            System.out.println ("response.status: " + response.status);

            if (response.statusCode == 200) {
                // check transaction chain
                // transactions come ordered from the oldest to the newest
                String prevHash = null;
                for (Serialization.Transaction tx : response.transactions) {
                    System.out.println ("Checking signature: " + tx.signature);
                    if (!Utils.checkSignature (tx.signature, tx.getSignable (), publicKey)) {
                        throw new AuditException ("Error checking signature of transaction");
                    }
                    // now we know tx.signature is correct... but is it signing the right prevHash?
                    if (prevHash != null && !prevHash.equals (tx.previousSignature)) {
                        throw new AuditException ("Transaction chain is broken: the previous signature contained in " +
                                "one transaction does not match the signature of the transaction that precedes it");
                    }
                    prevHash = tx.signature;
                }

                System.out.println ("\n");
                System.out.println ("----------------------------------");
                System.out.println ("-------Audit was successful-------");
                System.out.println ("----------------------------------");
                return response.transactions;
            }
            switch (response.status) {
                case ERROR_INVALID_KEY:
                    throw new InvalidKeyException ("The public key provided is not valid.");
                case ERROR_INVALID_LEDGER:
                    throw new InvalidLedgerException ("The public key provided isn't associated with any ledger.");
                case ERROR_SERVER_ERROR:
                default:
                    throw new ServerErrorException ("Error on the server side.");
            }
        } catch (InvalidKeyException | InvalidLedgerException | ServerErrorException | IOException | KeyException | InvalidServerResponseException | SignatureException e) {
            throw new AuditException ("Failed to audit the account of the public key provided. " + e);
        }
    }

    private <T> T sendPostRequest (ECPublicKey serverPublicKey, String url, ECPrivateKey privateKey, Object payload,
                                   Class<T> responseValueType)
            throws HttpRequest.HttpRequestException, IOException, SignatureException, InvalidServerResponseException,
            InvalidClientSignatureException {
        String payloadJson = Serialization.serialize (payload);
        String nonce = ((NonceContainer) payload).getNonce ();

        HttpRequest request = HttpRequest.post (url);
        //.header(Serialization.NONCE_HEADER_NAME, nonce);

        if (payload instanceof Signable) {
            String toSign = ((Signable) payload).getSignable ();
            // added the nonce to the signable message on the request
            request =
                    request.header (Serialization.SIGNATURE_HEADER_NAME, Utils.generateSignature (toSign, privateKey));
        }

        request.send (payloadJson);

        int responseCode = request.code ();

        String responseSignature = request.header (Serialization.SIGNATURE_HEADER_NAME);
        T response = Serialization.parse (request.body (), responseValueType);

        if (!(response instanceof Signable && response instanceof NonceContainer)) {
            throw new InvalidServerResponseException ("Response isn't signable or doesn't contain a nonce.\n " +
                    "Impossible to check if the sender was really the server.");
        }

        boolean result =
                Utils.checkSignature (responseSignature, ((Signable) response).getSignable (), serverPublicKey);
        if (!result) {
            throw new InvalidServerResponseException ("Server signatures do not match.");
        }

        String responseNonce = ((NonceContainer) response).getNonce ();
        System.out.println ("Client NONCE: " + nonce);
        System.out.println ("Server NONCE: " + responseNonce);
        System.out.println ("Server SIGN : " + responseSignature);
        if (!responseNonce.equals (nonce)) {
            throw new InvalidServerResponseException (
                    "The nonce received by the client do not match the one " + "he sent previously.");
        }

        if (responseCode != 200) {
            if (((Serialization.Response) response).status.equals (ERROR_NO_SIGNATURE_MATCH)) {
                throw new InvalidClientSignatureException (
                        "The message was reject by the server, because the " + "client signature didn't match.");
            }
        }

        return response;
    }

    private <T> T sendGetRequest (ECPublicKey serverPublicKey, String url, Class<T> responsValueType)
            throws HttpRequest.HttpRequestException, IOException, InvalidServerResponseException, SignatureException {
        String nonce = Utils.randomNonce ();
        HttpRequest request = HttpRequest.get (url).header (Serialization.NONCE_HEADER_NAME, nonce);

        int responseCode = request.code ();

        String responseSignature = request.header (Serialization.SIGNATURE_HEADER_NAME);
        T response = Serialization.parse (request.body (), responsValueType);

        if (!(response instanceof Signable && response instanceof NonceContainer)) {
            throw new InvalidServerResponseException ("Response isn't signable or doesn't contain a nonce.\n " +
                    "Impossible to check if the sender was really the server.");
        }

        boolean result =
                Utils.checkSignature (responseSignature, ((Signable) response).getSignable (), serverPublicKey);
        if (!result) {
            throw new InvalidServerResponseException ("Server signatures do not match.");
        }

        String responseNonce = ((NonceContainer) response).getNonce ();

        System.out.println ("Client NONCE: " + nonce);
        System.out.println ("Server NONCE: " + responseNonce);
        if (!responseNonce.equals (nonce)) {
            throw new InvalidServerResponseException (
                    "The nonce received by the server do not match the one " + "the client sent previously.");
        }

        return response;
    }

}
