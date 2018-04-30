package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.ServerInfo;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.SignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.InvalidValueException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.MissingLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.MissingTransactionException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Ledger;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.*;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Transaction;
import spark.Request;
import spark.Response;

import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.StatusMessage.*;
import static spark.Spark.*;


public class Main {
    private static Logger log;

    private static ECPublicKey serverPublicKey;
    private static ECPrivateKey serverPrivateKey;

    private static Object ledgerLock = new Object();

    private static List<ServerInfo> servers;
    
    public static void main(String[] args) throws FailedToLoadKeysException {

        try {
            loadKeys(args[0]);
            Database.setDatabaseName(args[0] + "_");
            log = Logger.getLogger(args[0] + "_logs");
            Ledger.log = Logger.getLogger(args[0] + "_" + Ledger.class.getName() + "_logs");
            Transaction.log = Logger.getLogger(args[0] + "_" + Transaction.class.getName() + "_logs");

            // set Loggers
            Utils.initLogger(log);
            Utils.initLogger(Ledger.log);
            Utils.initLogger(Transaction.log);

            Security.addProvider(new BouncyCastleProvider());
            log.log(Level.CONFIG, "Added bouncy castle security provider.");
            log.log(Level.INFO, "Loaded keys of the server.");

            log.log(Level.INFO, "Server identification: " + args[0]);
            log.log(Level.INFO, "Using port number " + args[1]);
            port(Integer.parseInt(args[1]));

            //Getting the replica servers information given by argument.
            servers = new ArrayList<>();
            for(int i = 2; i + 1 < args.length; i+=2) {
                Keypair keypair = loadKeypair(args[i+1]);
                ServerInfo serverInfo = new ServerInfo(new URL(args[i]), Serialization.publicKeyToBase64 (keypair.publicKey));
                servers.add(serverInfo);
            }

        } catch (KeyException | IOException e) {
            log.log(Level.SEVERE, "Failed to load keys from file. " + e);
            throw new FailedToLoadKeysException("Failed to load keys from file. " + e.getMessage(), e);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        try {
            Database.recreateSchema();
            log.log(Level.INFO, "Recreate database schema.");
        } catch (SQLException e) {
            log.log(Level.SEVERE, "Failed to recreate database schema. " + e);
            e.printStackTrace();
            System.exit(-1);
        }

        get("/servers", "application/json", (req, res) -> {
            try {
                Serialization.ServerListResponse response = new Serialization.ServerListResponse();
                response.nonce = req.headers(Serialization.NONCE_HEADER_NAME);

                log.log(Level.INFO, "Request received at: /servers \n" +
                        "data on the request: \n" +
                        "\tNONCE: " + req.headers(Serialization.NONCE_HEADER_NAME));

                response.servers = Main.servers;
                response.status = SUCCESS;
                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                ex.printStackTrace();
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a get servers request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        post("/register", "application/json", (req, res) -> {

            Serialization.RegisterRequest request = null;
            try {
                request = Serialization.parse(req, Serialization.RegisterRequest.class);
                Serialization.Response response = new Serialization.Response();
                response.nonce = request.initialTransaction.nonce;
                if (request.initialTransaction == null) {
                    response.status = ERROR_MISSING_PARAMETER;
                    log.log(Level.WARNING, "Missing initial transaction on register request.");
                    return prepareResponse(serverPrivateKey, req, res, response);
                }
                log.log(Level.INFO, "Request received at: /register \n" +
                        "data on the request: \n" +
                        "\tSIGNATURE: " + req.headers(Serialization.SIGNATURE_HEADER_NAME) + "\n" +
                        "\tNONCE: " + request.initialTransaction.nonce + "\n" +
                        "\tCLIENT BASE 64 PUBLIC KEY: " + request.initialTransaction.source + "\n" +
                        "\tAMOUNT: " + request.initialTransaction.amount);

                boolean result = false; // false to defend
                try {
                    //Recreate the hash with the data received
                    result = Utils.checkSignature(
                            req.headers(Serialization.SIGNATURE_HEADER_NAME),
                            request.getSignable(),
                            request.initialTransaction.source);

                    System.out.println("SIGN val: " + result);
                } catch (SignatureException e) {
                    log.log(Level.WARNING, "The signature of the message received from the client doesn't match " +
                            "with the signature of the message generated by the server. " + e);
                }

                if (!result) {
                    res.status(401);
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    log.log(Level.WARNING, "Client signature not verified.");
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that the register request was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    // mutual exclusion is necessary to ensure the new ledger ID obtained in "new Ledger"
                    // is still correct/"fresh" when "ledger.persist" is called.
                    synchronized (ledgerLock) {
                        Ledger ledger = new Ledger(conn, Serialization.base64toPublicKey(request.initialTransaction.source), request.initialTransaction);
                        ledger.persist(conn);
                        conn.commit();
                    }
                    response.status = SUCCESS;
                    log.log(Level.INFO, "Initialized a new ledger with the base 64 public key: " + request.initialTransaction.source);
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
                    response.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (InvalidLedgerException e) {
                    response.status = ERROR_INVALID_LEDGER;
                } catch (InvalidAmountException e) {
                    response.status = ERROR_INVALID_AMOUNT;
                } catch (InvalidKeyException e) {
                    response.status = ERROR_INVALID_KEY;
                } finally {
                    if (!response.status.equals(SUCCESS) && conn != null) {
                        conn.rollback();
                        log.log(Level.SEVERE, "The ledger created with the following public key was not " +
                                "persisted. Public Key: " + request.initialTransaction.source);
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.nonce = (request != null && request.initialTransaction != null ? request.initialTransaction.nonce : "");
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a register request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        post("/sendAmount", "application/json", (req, res) -> {
            try {
                Serialization.SendAmountRequest request = Serialization.parse(req,
                        Serialization.SendAmountRequest.class);
                log.log(Level.INFO, "Request received at: /sendAmount \n" +
                        "data on the request:" +
                        "SIGNATURE: " + req.headers(Serialization.SIGNATURE_HEADER_NAME) + "\n" +
                        "NONCE: " + request.nonce + "\n" +
                        "AMOUNT:" + request.amount + "\n" +
                        "SOURCE CLIENT BASE 64 PUBLIC KEY: " + request.source + "\n" +
                        "TARGET CLIENT BASE 64 PUBLIC KEY: " + request.target);

                Serialization.Response response = new Serialization.Response();
                response.nonce = request.nonce;

                //Recreate the hash with the data received
                boolean result = Utils.checkSignature(
                        req.headers(Serialization.SIGNATURE_HEADER_NAME),
                        request.getSignable(),
                        request.source);

                if (!result) {
                    res.status(401);
                    log.log(Level.WARNING, "Mismatch in request signatures");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that the transaction was created by the owner of its respective private key.
                ///////////////////////////////////////////////////

                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    Ledger sourceLedger = Ledger.load(conn, Serialization.base64toPublicKey(request.source));
                    Ledger targetLedger = Ledger.load(conn, Serialization.base64toPublicKey(request.target));

                    // mutual exclusion is necessary to ensure the new transaction ID obtained in "new Transaction"
                    // is still correct/"fresh" when "transaction.persist" is called, and also that the latest
                    // transaction is still the latest transaction
                    synchronized (ledgerLock) {
                        Transaction transaction = new Transaction(conn, sourceLedger, targetLedger, request.amount,
                                request.nonce,
                                request.signature,
                                request.previousSignature, Transaction.TransactionTypes.SENDING);
                        // checkout the amount from the source ledger
                        sourceLedger.setAmount(sourceLedger.getAmount() - request.amount);
                        transaction.persist(conn);
                        sourceLedger.persist(conn);
                    }
                    conn.commit();
                    response.status = SUCCESS;
                    log.log(Level.INFO, "Transaction created with success.");
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
                    response.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (MissingLedgerException e) {
                    response.status = ERROR_INVALID_LEDGER;
                } catch (InvalidKeyException e) {
                    response.status = ERROR_INVALID_KEY;
                } catch (SignatureException e) {
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                } finally {
                    if ((response.status == null || !response.status.equals(SUCCESS)) && conn != null) {
                        conn.rollback();
                        log.log(Level.SEVERE, "The transaction created was not persisted, due to an error.");
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a send amount request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        get("/checkAccount/:key", "application/json", (req, res) -> {
            try {
                // init generic response to use when an error occur
                Serialization.Response errorResponse = new Serialization.Response();
                errorResponse.nonce = req.headers(Serialization.NONCE_HEADER_NAME);
                String pubKeyBase64 = req.params(":key");
                if (pubKeyBase64 == null) {
                    errorResponse.status = ERROR_MISSING_PARAMETER;
                    return prepareResponse(serverPrivateKey, req, res, errorResponse);
                }
                log.log(Level.INFO, "Checking account with public key: " + pubKeyBase64);

                Connection conn = null;
                boolean committed = false;
                try {
                    Serialization.CheckAccountResponse response = new Serialization.CheckAccountResponse();
                    ECPublicKey clientPublicKey = Serialization.base64toPublicKey(pubKeyBase64);
                    conn = Database.getConnection();
                    Ledger ledger = Ledger.load(conn, clientPublicKey);
                    response.nonce = req.headers(Serialization.NONCE_HEADER_NAME);
                    System.out.println("Pending" + ledger.getPendingTransactions(conn, clientPublicKey));
                    response.balance = ledger.getAmount();
                    response.pendingTransactions = serializeTransactions(ledger.getPendingTransactions(conn, clientPublicKey));
                    System.out.println("Balance: " + response.balance);

                    response.status = SUCCESS;
                    log.log(Level.INFO, "Successful check account operation of the ledger with " +
                            "public key: " + pubKeyBase64);
                    conn.commit();
                    committed = true;
                    return prepareResponse(serverPrivateKey, req, res, response);
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
                    errorResponse.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (MissingLedgerException e) {
                    errorResponse.status = ERROR_INVALID_LEDGER;
                } catch (InvalidKeyException e) {
                    errorResponse.status = ERROR_INVALID_KEY;
                } finally {
                    if (conn != null && !committed) {
                        conn.rollback();
                    }
                }
                return prepareResponse(serverPrivateKey, req, res, errorResponse);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a check account request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        post("/receiveAmount", "application/json", (req, res) -> {
            try {
                Serialization.ReceiveAmountRequest request = Serialization.parse(req,
                        Serialization.ReceiveAmountRequest.class);
                log.log(Level.INFO, "Request received at: /receiveAmount \n" +
                        "data on the request:" +
                        "SIGNATURE: " + req.headers(Serialization.SIGNATURE_HEADER_NAME) + "\n" +
                        "NONCE: " + request.transaction.nonce + "\n" +
                        "AMOUNT:" + request.transaction.amount + "\n" +
                        "SOURCE PUBLIC KEY: " + request.transaction.source + "\n" +
                        "TARGET PUBLIC KEY: " + request.transaction.target + "\n" +
                        "PENDING TRANSACTION: " + request.pendingTransactionHash);

                Serialization.Response response = new Serialization.Response();
                response.nonce = request.transaction.nonce;

                //Recreate the hash with the data received
                boolean result = Utils.checkSignature(
                        req.headers(Serialization.SIGNATURE_HEADER_NAME),
                        request.getSignable(),
                        request.transaction.source);

                if (!result) {
                    res.status(401);
                    log.log(Level.WARNING, "Mismatch in request signatures");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that *the whole request* was created by the owner of its respective private key.
                ///////////////////////////////////////////////////

                // now check the transaction itself
                result = Utils.checkSignature(
                        request.transaction.signature,
                        request.transaction.getSignable(),
                        request.transaction.source);

                if (!result) {
                    res.status(401);
                    log.log(Level.WARNING, "Mismatch in transaction signatures");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    Ledger sourceLedger = Ledger.load(conn, Serialization.base64toPublicKey(request.transaction.source));
                    Ledger targetLedger = Ledger.load(conn, Serialization.base64toPublicKey(request.transaction.target));

                    // mutual exclusion is necessary to ensure the new transaction ID obtained in "new Transaction"
                    // is still correct/"fresh" when "transaction.persist" is called, and also that the latest
                    // transaction is still the latest transaction
                    synchronized (ledgerLock) {
                        Transaction pendingTransaction = Transaction.getTransactionByHash(conn, request.pendingTransactionHash);

                        if (!pendingTransaction.isPending()) {
                            throw new MissingTransactionException("Transaction mentioned in the request is invalid or not pending");
                        }

                        Transaction transaction = new Transaction(conn, sourceLedger, targetLedger,
                                request.transaction.amount,
                                request.transaction.nonce,
                                request.transaction.signature,
                                request.transaction.previousSignature, Transaction.TransactionTypes.RECEIVING);

                        // the Transaction constructor already did some validation, now validate the things that
                        // are specific to RECEIVING transactions
                        if (transaction.getSourceLedger().getId() != pendingTransaction.getTargetLedger().getId() ||
                                transaction.getTargetLedger().getId() != pendingTransaction.getSourceLedger().getId()) {
                            throw new MissingTransactionException("Transaction source/target do not match with pending transaction");
                        }

                        if (transaction.getAmount() != pendingTransaction.getAmount()) {
                            throw new InvalidAmountException("Transaction amount does not match with pending transaction", transaction.getAmount());
                        }
                        // add the amount to the source ledger
                        sourceLedger.setAmount(sourceLedger.getAmount() + request.transaction.amount);

                        // the sending transaction is not pending anymore
                        pendingTransaction.setPending(false);
                        pendingTransaction.persist(conn);
                        transaction.persist(conn);
                        sourceLedger.persist(conn);
                    }
                    conn.commit();
                    response.status = SUCCESS;
                    log.log(Level.INFO, "Transaction created with success.");
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
                    response.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (MissingLedgerException e) {
                    response.status = ERROR_INVALID_LEDGER;
                } catch (InvalidAmountException e) {
                    response.status = ERROR_INVALID_AMOUNT;
                } catch (MissingTransactionException e) {
                    response.status = ERROR_INVALID_VALUE;
                } catch (InvalidKeyException e) {
                    response.status = ERROR_INVALID_KEY;
                } catch (SignatureException e) {
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                } finally {
                    if ((response.status == null || !response.status.equals(SUCCESS)) && conn != null) {
                        conn.rollback();
                        log.log(Level.SEVERE, "The transaction created was not persisted, due to an error.");
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a send amount request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        get("/audit/:key", "application/json", (req, res) -> {
            Serialization.Response errorResponse = new Serialization.Response();
            errorResponse.nonce = req.headers(Serialization.NONCE_HEADER_NAME);
            String pubKeyBase64 = req.params(":key");
            if (pubKeyBase64 == null) {
                errorResponse.status = ERROR_MISSING_PARAMETER;
                return prepareResponse(serverPrivateKey, req, res, errorResponse);
            }
            log.log(Level.INFO, "Going to send audit data for public key: " + pubKeyBase64);

            Connection conn = null;
            try {
                Serialization.AuditResponse response = new Serialization.AuditResponse();
                response.nonce = req.headers(Serialization.NONCE_HEADER_NAME);
                conn = Database.getConnection();
                ECPublicKey publicKey = Serialization.base64toPublicKey(req.params(":key"));
                Ledger ledger = Ledger.load(conn, publicKey);

                response.transactions = serializeTransactions(ledger.getAllTransactions(conn));
                conn.commit();
                response.status = SUCCESS;
                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (MissingLedgerException e) {
                errorResponse.status = ERROR_INVALID_LEDGER;
            } catch (InvalidKeyException e) {
                errorResponse.status = ERROR_INVALID_KEY;
            } catch (SQLException e) {
                // servers fault
                log.log(Level.SEVERE, "Error related with the database. " + e);
                errorResponse.status = ERROR_SERVER_ERROR;
            } finally {
                if (conn != null) {
                    try {
                        conn.rollback();
                    } catch (SQLException ex) {
                        // if we can't even rollback, this is now a server error
                        errorResponse.status = ERROR_SERVER_ERROR;
                    }
                }
            }
            return prepareResponse(serverPrivateKey, req, res, errorResponse);
        });
    }

    private static String prepareResponse(ECPrivateKey privateKey, Request sparkRequest, Response sparkResponse, Serialization.Response response) throws JsonProcessingException, SignatureException {

        if (response.statusCode < 0) {
            // try to guess a status code from the status string
            switch (response.status) {
                case SUCCESS:
                    response.statusCode = 200;
                    break;
                case ERROR_SERVER_ERROR:
                    response.statusCode = 500;
                    break;
                default:
                    // all other errors are problems with the request
                    response.statusCode = 400;
            }
        }
        String signature = Utils.generateSignature(response.getSignable(), privateKey);
        sparkResponse.status(response.statusCode);
        sparkResponse.header(Serialization.SIGNATURE_HEADER_NAME, signature);
        sparkResponse.type("application/json");
        return Serialization.serialize(response);
    }

    private static void loadKeys(String serverName) throws KeyException, IOException, URISyntaxException {
        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\server";
        String filepath = root + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + serverName + ".keys";
        Path path = Paths.get(filepath).normalize();

        serverPublicKey = Utils.readPublicKeyFromFile(path.toString());
        serverPrivateKey = Utils.readPrivateKeyFromFile(path.toString());
    }

    static class Keypair {
        public ECPublicKey publicKey;
        public ECPrivateKey privateKey;
    }

    private static Keypair loadKeypair(String serverName) throws KeyException, IOException, URISyntaxException {
        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\server";
        String filepath = root + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + serverName + ".keys";
        Path path = Paths.get(filepath).normalize();
        Keypair keypair = new Keypair();
        keypair.publicKey = Utils.readPublicKeyFromFile(path.toString());
        keypair.privateKey = Utils.readPrivateKeyFromFile(path.toString());
        return keypair;
    }

    private static List<Serialization.Transaction> serializeTransactions(List<Transaction> transactions) throws KeyException {
        List<Serialization.Transaction> serializedTransactions = new ArrayList<>();
        for (Transaction tx : transactions) {
            Serialization.Transaction serializedTx = new Serialization.Transaction();
            serializedTx.source = Serialization.publicKeyToBase64(tx.getSourceLedger().getPublicKey());
            serializedTx.target = Serialization.publicKeyToBase64(tx.getTargetLedger().getPublicKey());
            serializedTx.isSend = tx.getTransactionType() == Transaction.TransactionTypes.SENDING;
            serializedTx.amount = tx.getAmount();
            serializedTx.nonce = tx.getNonce();
            serializedTx.previousSignature = tx.getPreviousHash() == null ? "" : tx.getPreviousHash();
            serializedTx.signature = tx.getHash();
            serializedTransactions.add(serializedTx);
        }
        return serializedTransactions;
    }
}