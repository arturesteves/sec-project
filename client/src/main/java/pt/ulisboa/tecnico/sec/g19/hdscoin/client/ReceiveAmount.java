package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.AuditException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CheckAccountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.ReceiveAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;


public class ReceiveAmount {

    public static final String SERVER_URL = "http://localhost:4570";

    public static void main (String[] args) throws ReceiveAmountException {
        String clientName;
        String transactionSignature;
        int numberOfServers;
        String password;

        // create options
        Options registerOptions = new Options ();
        registerOptions.addOption ("n", true, "The name of the client name that is receiving.");
        registerOptions.addOption ("ts", true, "Signature of the transaction to receive the amount.");
        registerOptions.addOption ("ns", true, "Number of servers");
        registerOptions.addOption ("pw", true, "Password to access to obtain the private key from the key store");

        CommandLineParser parser = new BasicParser ();
        CommandLine cmd = null;

        try {
            cmd = parser.parse (registerOptions, args);
        } catch (ParseException e) {
            throw new ReceiveAmountException ("Can't receive amount, because arguments are missing. " + e);
        }

        if (cmd.hasOption ("n") && !cmd.getOptionValue ("n").trim ().equals ("")) {
            clientName = cmd.getOptionValue ("n");
        } else {
            usage (registerOptions);
            throw new ReceiveAmountException ("Can't receive amount, the name of the client is missing.");
        }
        if (cmd.hasOption ("ts") && !cmd.getOptionValue ("ts").trim ().equals ("")) {
            transactionSignature = cmd.getOptionValue ("ts");
        } else {
            usage (registerOptions);
            throw new ReceiveAmountException ("Can't receive amount, the transaction signature is missing.");
        }
        if (cmd.hasOption ("ns") && !cmd.getOptionValue ("ns").trim ().equals ("")) {
            numberOfServers = Integer.parseInt (cmd.getOptionValue ("ns"));
        } else {
            usage (registerOptions);
            throw new ReceiveAmountException ("Can't receive amount, number of servers available is missing.");
        }
        if (cmd.hasOption ("pw") && !cmd.getOptionValue ("pw").trim ().equals ("")) {
            password = cmd.getOptionValue ("pw");
        } else {
            usage (registerOptions);
            throw new ReceiveAmountException ("Failed to receive amount. Missing the -pw option.");
        }

        String root = Paths.get (System.getProperty ("user.dir")).getParent ().toString () + "\\common";
        String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
        Path path = Paths.get (filepath).normalize ();

        try {
            KeyStore keyStore = Utils.initKeyStore (path.toString ());
            ECPublicKey sourcePublicKey = Utils.loadPublicKeyFromKeyStore (keyStore, clientName);
            ECPrivateKey sourcePrivateKey = Utils.loadPrivateKeyFromKeyStore (path.toString (), clientName, password);

            IClient client = new Client (new URL (SERVER_URL), numberOfServers, path.toString ());

            // check account to get pending incoming transactions
            Serialization.Transaction pendingTx = null;
            CheckAccountResult result = client.checkAccount (sourcePublicKey);
            for (Serialization.Transaction tx : result.pendingTransactions) {
                if (tx.signature.equals (transactionSignature)) {
                    pendingTx = tx;
                }
            }

            if (pendingTx == null) {
                throw new ReceiveAmountException ("A pending transaction with the specified signature was not found");
            }

            // get the hash of our last transaction, so we can include it in the new transaction
            // client.audit verifies the transaction chain for us
            List<Serialization.Transaction> transactions = client.audit (sourcePublicKey);
            // transactions.size() should always be > 0 because of the dummy transaction required to open an account
            if (transactions.size () == 0) {
                throw new ReceiveAmountException (
                        "Ledger has too few transactions (account appears to not have been initialized on the server)");
            }
            String previousSignature = transactions.get (transactions.size () - 1).signature;

            // pendingTx.source is the target of the receiving transaction
            client.receiveAmount (sourcePublicKey, pendingTx.source, pendingTx.amount, sourcePrivateKey,
                    previousSignature, transactionSignature);

        } catch (AuditException e) {
            throw new ReceiveAmountException ("Failed to audit ledger. " + e);
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException |
                UnrecoverableKeyException | CheckAccountException e) {
            throw new ReceiveAmountException ("Failed to receive amount. " + e);
        }

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter ();
        formatter.printHelp ("ReceiveAmount", options);
    }

}
