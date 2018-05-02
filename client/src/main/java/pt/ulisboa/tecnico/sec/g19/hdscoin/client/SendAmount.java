package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.ReceiveAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.SendAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.AuditException;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;


public class SendAmount {
    // contains the protocol and host used and the initial port used
    public static final String SERVER_URL = "http://localhost:4570";

    public static void main(String[] args) throws SendAmountException {
        String clientNameSource;
        String clientNameTarget;
        int amount;
        int numberOfServers;
        String password;

        // create options
        Options registerOptions = new Options();
        registerOptions.addOption("ns", true, "The name of the client that is sending the amount.");
        registerOptions.addOption("nt", true, "The name of the client that is receiving.");
        registerOptions.addOption("s", true, "Server name");
        registerOptions.addOption("a", true, "Amount to send.");
        registerOptions.addOption ("ns", true, "Number of servers");
        registerOptions.addOption ("pw", true, "Password to access to obtain the private key from the key store");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(registerOptions, args);
        } catch (ParseException e) {
            throw new SendAmountException("Can't send amount, because arguments are missing. " + e);
        }

        if (cmd.hasOption("ns") && !cmd.getOptionValue("ns").trim().equals("")) {
            clientNameSource = cmd.getOptionValue("ns");
        } else {
            usage(registerOptions);
            throw new SendAmountException("Can't send amount, the name of the source client is missing.");
        }
        if (cmd.hasOption("nt") && !cmd.getOptionValue("nt").trim().equals("")) {
            clientNameTarget = cmd.getOptionValue("nt");
        } else {
            usage(registerOptions);
            throw new SendAmountException("Can't send amount, the name of the target client is missing.");
        }
        if (cmd.hasOption("a") && !cmd.getOptionValue("a").trim().equals("")) {
            try {
                amount = Integer.parseInt(cmd.getOptionValue("a"));
            } catch (NullPointerException | NumberFormatException e) {
                throw new SendAmountException("Can't send amount, the amount is invalid. " + e);
            }
        } else {
            usage(registerOptions);
            throw new SendAmountException("Can't send amount, the amount is missing.");
        }
        if (cmd.hasOption ("ns") && !cmd.getOptionValue ("ns").trim ().equals ("")) {
            numberOfServers = Integer.parseInt (cmd.getOptionValue ("ns"));
        } else {
            usage (registerOptions);
            throw new SendAmountException ("Can't send amount, number of servers available is missing.");
        }
        if (cmd.hasOption ("pw") && !cmd.getOptionValue ("pw").trim ().equals ("")) {
            password = cmd.getOptionValue ("pw");
        } else {
            usage (registerOptions);
            throw new SendAmountException ("Failed to send amount. Missing the -pw option.");
        }

        String root = Paths.get (System.getProperty ("user.dir")).getParent ().toString () + "\\common";
        String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
        Path path = Paths.get (filepath).normalize ();

        try {
            KeyStore keyStore = Utils.initKeyStore (path.toString ());
            ECPublicKey sourcePublicKey = Utils.loadPublicKeyFromKeyStore (keyStore, clientNameSource);
            ECPrivateKey sourcePrivateKey = Utils.loadPrivateKeyFromKeyStore (path.toString (), clientNameSource, password);
            ECPublicKey targetPublicKey = Utils.loadPublicKeyFromKeyStore (keyStore, clientNameTarget);

            IClient client = new Client(new URL(SERVER_URL), numberOfServers, path.toString ());
            // get the hash of our last transaction, so we can include it in the new transaction
            // client.audit verifies the transaction chain for us
            List<Serialization.Transaction> transactions = client.audit(sourcePublicKey);
            // transactions.size() should always be > 0 because of the dummy transaction required to open an account
            if(transactions.size() == 0) {
                throw new SendAmountException("Ledger has too few transactions (account appears to not have been initialized on the server)");
            }
            String previousSignature = transactions.get(transactions.size() - 1).signature;
            client.sendAmount(sourcePublicKey, targetPublicKey, amount, sourcePrivateKey, previousSignature);

        } catch (IOException e) {
            throw new SendAmountException("Failed to create a transaction. " + e);
        } catch (AuditException e) {
            throw new SendAmountException("Self-auditing failed. " + e);
        } catch (Exception e) {
            throw new SendAmountException("Failed to send amount. " + e);
        }

    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("SendAmount", options);
    }

}
