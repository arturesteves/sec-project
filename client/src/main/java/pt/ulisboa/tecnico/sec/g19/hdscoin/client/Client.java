package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import com.github.kevinsawicki.http.HttpRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Readable;
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
import java.util.*;

import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.SERVER_PREFIX;
import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.StatusMessage.ERROR_NO_SIGNATURE_MATCH;


public class Client implements IClient {


    static {
        Security.addProvider (new BouncyCastleProvider ());
    }

    private List<ServerInfo> servers;
    private List<ServerInfo> ackList;
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
                serverInfo.serverUrl =
                        new URL (url.getProtocol () + "://" + url.getHost () + ":" + (url.getPort () + i));
                serverInfo.publicKeyBase64 = Serialization.publicKeyToBase64 (
                        Utils.loadPublicKeyFromKeyStore (keyStore, SERVER_PREFIX + (i + 1)));
                serverInfos.add (serverInfo);
            }
            return serverInfos;
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyException e) {
            e.printStackTrace ();
            throw new RuntimeException (e);
        }
    }


    ////////////////////////////////////////////////
    //// public methods
    ////////////////////////////////////////////////

    @Override public void register (ECPublicKey publicKey, ECPrivateKey privateKey, int amount)
            throws RegisterException, KeyException, SignatureException {
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

        for (ServerInfo server : this.servers) {
            try {
                register (server, request, privateKey);
            } catch (Exception e) {
                System.out.println ("Received a bad response from a replica...");
            }
        }
        if (receivedMajorityAcknowledge ()) {
            this.ackList.clear ();
            System.out.println ();
            System.out.println ("---------------------------------");
            System.out.println ("---Registration was successful---");
            System.out.println ("---------------------------------");
            System.out.println ();
        } else {
            this.ackList.clear ();
            throw new RegisterException ("Failed to register - not enough success responses!");
        }
    }

    // write operation
    @Override public void sendAmount (ECPublicKey sourcePublicKey, ECPublicKey targetPublicKey, int amount,
                                      ECPrivateKey sourcePrivateKey, String previousSignature)
            throws SendAmountException, AuditException, KeyException, SignatureException {

        // GET A LEDGER FIRST
        Serialization.AuditResponse auditResponse = audit (sourcePublicKey);
        Serialization.Ledger ledger = auditResponse.ledger;

        String b64SourcePublicKey = Serialization.publicKeyToBase64 (sourcePublicKey);
        String b64DestinationPublicKey = Serialization.publicKeyToBase64 (targetPublicKey);

        Serialization.SendAmountRequest request = new Serialization.SendAmountRequest ();
        request.ledger = ledger;
        request.ledger.timestamp++;
        request.source = b64SourcePublicKey;
        request.target = b64DestinationPublicKey;
        request.amount = amount;
        request.nonce = Utils.randomNonce ();
        request.previousSignature = previousSignature;
        request.signature = Utils.generateSignature (request.getSignable (), sourcePrivateKey);


        for (ServerInfo server : this.servers) {
            try {
                sendAmount (server, request, sourcePrivateKey);
            } catch (Exception e) {
                System.out.println ("Received a bad response from a replica...");
            }
        }

        if (receivedMajorityAcknowledge ()) {
            this.ackList.clear ();
            System.out.println ();
            System.out.println ("--------------------------------");
            System.out.println ("---Transaction was successful---");
            System.out.println ("--Waiting for target to accept--");
            System.out.println ("--------------------------------");
            System.out.println ();
        } else {
            this.ackList.clear();
            throw new SendAmountException ("Failed to send amount - not enough success responses!");
        }
    }

    // write operation
    @Override public void receiveAmount (ECPublicKey sourcePublicKey, String targetPublicKey, int amount,
                                         ECPrivateKey sourcePrivateKey, String previousSignature,
                                         String incomingSignature)
            throws ReceiveAmountException, KeyException, SignatureException, AuditException {

        // GET A LEDGER FIRST
        Serialization.AuditResponse auditResponse = audit (sourcePublicKey);
        Serialization.Ledger ledger = auditResponse.ledger;

        String b64SourcePublicKey = Serialization.publicKeyToBase64 (sourcePublicKey);
        String b64DestinationPublicKey = targetPublicKey;

        Serialization.ReceiveAmountRequest request = new Serialization.ReceiveAmountRequest ();
        request.transaction = new Serialization.Transaction ();
        request.ledger = ledger;
        request.ledger.timestamp++;
        request.transaction.source = b64SourcePublicKey;
        request.transaction.target = b64DestinationPublicKey;
        request.transaction.amount = amount;
        request.transaction.nonce = Utils.randomNonce ();
        request.transaction.previousSignature = previousSignature;
        // signature for just the transaction:
        request.transaction.signature = Utils.generateSignature (request.transaction.getSignable (), sourcePrivateKey);
        request.pendingTransactionHash = incomingSignature;
        // signature for the whole request (including transaction):

        for (ServerInfo server : this.servers) {
            try {
                receiveAmount (server, request, sourcePrivateKey);
            } catch (Exception e) {
                System.out.println ("Received a bad response from a replica...");
            }
        }

        if (receivedMajorityAcknowledge ()) {
            this.ackList.clear ();
            System.out.println ();
            System.out.println ("---------------------------------------");
            System.out.println ("---Transaction accepted successfully---");
            System.out.println ("---------------------------------------");
            System.out.println ();
        } else {
            this.ackList.clear ();
            throw new ReceiveAmountException ("Failed to receive amount - not enough success responses!");
        }
    }

    // read operation
    @Override public Serialization.CheckAccountResponse checkAccount (ECPublicKey publicKey) throws CheckAccountException {
        List<Serialization.CheckAccountResponse> checkAccountResults = new ArrayList<> ();
        for (ServerInfo server : this.servers) {
            try {
                checkAccountResults.add (checkAccount (server, publicKey));
            } catch (Exception e) {
                System.out.println ("Received a bad response from a replica...");
            }
        }

        if (receivedReadMajority (checkAccountResults)) {
            System.out.println ("\n");
            System.out.println ("----------------------------------");
            System.out.println ("---Check account was successful---");
            System.out.println ("----------------------------------");
            //return checkAccountResults.get (0);  // choose anyone
            return getValueWithMajorityTimestamp(checkAccountResults);
        } else {
            throw new CheckAccountException ("Failed to check account - not enough success responses!");
        }
    }

    // read operation
    @Override public Serialization.AuditResponse audit (ECPublicKey publicKey) throws AuditException {
        List<Serialization.AuditResponse> auditResponses = new ArrayList<> ();
        for (ServerInfo server : this.servers) {
            try {
                auditResponses.add (audit (server, publicKey));
            } catch (Exception e) {
                System.out.println ("Received a bad response from a replica...");
            }

        }

        if (receivedReadMajority (auditResponses)) {
            System.out.println ("\n");
            System.out.println ("----------------------------------");
            System.out.println ("-------Audit was successful-------");
            System.out.println ("----------------------------------");
            //return auditResponses.get (0);  // choose anyone
            return getValueWithMajorityTimestamp(auditResponses);
        } else {
            throw new AuditException ("Failed to audit account - not enough success responses!");
        }
    }


    ////////////////////////////////////////////////
    //// private methods
    ////////////////////////////////////////////////

    private void register (ServerInfo server, Serialization.RegisterRequest request, ECPrivateKey privateKey)
            throws RegisterException {
        try {
            // log
            System.out.println ();
            System.out.println ("---------------------");
            System.out.println ("---Sending Request---");
            System.out.println ("Sending to: " + server.serverUrl.toString ());
            System.out.println ("Base 64 Public Key: " + request.initialTransaction.source);
            System.out.println ("Amount: " + request.initialTransaction.amount);
            System.out.println ("Nonce: " + request.initialTransaction.nonce);
            System.out.println ("Signature: " + request.initialTransaction.signature);
            System.out.println ("---------------------");
            System.out.println ();

            // http post request
            Serialization.Response response = sendPostRequest (Serialization.base64toPublicKey (server.publicKeyBase64),
                    server.serverUrl.toString () + "/register", privateKey, request, Serialization.Response.class);

            if (response.statusCode == 200) {
                this.ackList.add (server);

            } else {
                switch (response.status) {
                    case ERROR_INVALID_KEY:
                        throw new InvalidKeyException ("The public key provided is not valid.");
                    case ERROR_INVALID_AMOUNT:
                        throw new InvalidAmountException ("The amount provided is invalid.",
                                request.initialTransaction.amount);
                    case ERROR_INVALID_LEDGER:
                        throw new InvalidLedgerException ("The public key is already associated with a ledger.");
                    case ERROR_SERVER_ERROR:
                        throw new ServerErrorException ("Error on the server side.");
                }
            }

        } catch (HttpRequest.HttpRequestException | IOException | KeyException | SignatureException | InvalidServerResponseException | InvalidClientSignatureException | InvalidKeyException | InvalidLedgerException | ServerErrorException e) {
            throw new RegisterException ("Failed to register the public key provided. " + e, e);
        } catch (InvalidAmountException e) {
            e.printStackTrace ();
        }
    }


    ////////////////////////////////////////////////
    //// WRITE OPERATIONS
    ////////////////////////////////////////////////

    private void sendAmount (ServerInfo server, Serialization.SendAmountRequest request, ECPrivateKey sourcePrivateKey)
            throws SendAmountException {
        try {
            // log
            System.out.println ();
            System.out.println ("---------------------");
            System.out.println ("---Sending Request---");
            System.out.println ("Sending to: " + server.serverUrl.toString ());
            System.out.println ("Ledger timestamp: " + request.ledger.timestamp);
            System.out.println ("Nonce: " + request.nonce);
            System.out.println ("Previous signature: " + request.previousSignature);
            System.out.println ("Signature: " + request.signature);
            System.out.println ("Get Signable: " + request.getSignable ());
            System.out.println ("Private key: " + sourcePrivateKey);
            System.out.println ("---------------------");
            System.out.println ();

            Serialization.Response response = sendPostRequest (Serialization.base64toPublicKey (server.publicKeyBase64),
                    server.serverUrl.toString () + "/sendAmount", sourcePrivateKey, request,
                    Serialization.Response.class);

            if (response.statusCode == 200) {
                this.ackList.add (server);

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

    private void receiveAmount (ServerInfo server, Serialization.ReceiveAmountRequest request,
                                ECPrivateKey sourcePrivateKey) throws ReceiveAmountException {
        try {

            Serialization.Response response = sendPostRequest (Serialization.base64toPublicKey (server.publicKeyBase64),
                    server.serverUrl.toString () + "/receiveAmount", sourcePrivateKey, request,
                    Serialization.Response.class);

            if (response.statusCode == 200) {
                this.ackList.add (server);

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

    ////////////////////////////////////////////////
    //// READ OPERATIONS
    ////////////////////////////////////////////////

    private Serialization.CheckAccountResponse checkAccount (ServerInfo server, ECPublicKey publicKey) throws CheckAccountException {
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
                // the read list is not needed, because on the other check account we are storing the results
                return response; //new CheckAccountResult (response.balance, response.pendingTransactions);

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

    private Serialization.AuditResponse audit (ServerInfo server, ECPublicKey publicKey) throws AuditException {
        try {
            String b64PublicKey = Serialization.publicKeyToBase64 (publicKey);
            System.out.println ("base64 encoded: " + URLEncoder.encode (b64PublicKey, "UTF-8"));
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
                for (Serialization.Transaction tx : response.ledger.transactions) {
                    System.out.println ("Checking signature: " + tx.signature);
                    if (!Utils.checkSignature (tx.signature, tx.getSignable (), publicKey)) {
                        System.out.println ("Error checking signature of transaction");
                        throw new AuditException ("Error checking signature of transaction");
                    }
                    // now we know tx.signature is correct... but is it signing the right prevHash?
                    if (prevHash != null && !prevHash.equals (tx.previousSignature)) {
                        System.out.println ("Transaction chain is broken");
                        throw new AuditException ("Transaction chain is broken: the previous signature contained in " +
                                "one transaction does not match the signature of the transaction that precedes it");
                    }
                    prevHash = tx.signature;
                }

                return response;
            }
            System.out.println ("response error: " + response.status);
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
            e.printStackTrace ();
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
            String s = Utils.generateSignature (toSign, privateKey);
            request = request.header (Serialization.SIGNATURE_HEADER_NAME, s);
            System.out.println ("REQUEST SIGNATURE: " + s);
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

    private boolean receivedMajorityAcknowledge () {
        return hasMajority (this.ackList);
    }

    private <T> boolean receivedReadMajority (List<T> readables) {
        return hasMajority (readables);
    }

    private <T> boolean hasMajority (List<T> list) {
        return list.size () > (servers.size () + numberOfMaxFaults) / 2;
    }

    private <T> T getValueWithMajorityTimestamp(List<T> list) {
        // get the occurrences of a timestamp in the list
        HashMap<Integer, Integer> timestampsOccurrence = getTimestampsOccurrence (list);
        // get the highest timestamp
        int highestTimestamp = getHighestTimestampOccurrence (timestampsOccurrence);
        // fetch the first value with the highest timestamp
        return getValueWithHighestTimestampOccurrence (list, highestTimestamp);
    }

    private <T> HashMap<Integer, Integer> getTimestampsOccurrence (List<T> list) {
        HashMap<Integer, Integer> timestampsOccurrence = new HashMap<> ();
        for(T element : list) {
            Readable readable = (Readable) element;
            System.out.println ("Timestamp: " + readable.getTimestamp ());
            if (timestampsOccurrence.containsKey (readable.getTimestamp ())) {
                int occurrence = timestampsOccurrence.get (readable.getTimestamp ());
                timestampsOccurrence.put (readable.getTimestamp (), occurrence+1);
            } else {
                timestampsOccurrence.put (readable.getTimestamp (), 1);
            }
        }
        return timestampsOccurrence;
    }

    private int getHighestTimestampOccurrence (HashMap<Integer, Integer> occurrences) {
        int highestTimestamp = 0;
        int oldOccurence = 0;
        Iterator it = occurrences.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            int value = (Integer) pair.getValue ();
            if (value > oldOccurence) {
                oldOccurence = value;
                highestTimestamp = (Integer) pair.getKey ();
                System.out.println ("New highest timestamp: " + highestTimestamp + "; occurred " + oldOccurence + " times.");
            }
            System.out.println(pair.getKey() + " = " + pair.getValue());
        }
        return highestTimestamp;
    }

    private <T> T getValueWithHighestTimestampOccurrence(List<T> list, int timestamp) {
        for (T element : list) {
            Readable readable = (Readable) element;
            if (readable.getTimestamp () == timestamp) {
                return element;
            }
        }
        return null;
    }

}
