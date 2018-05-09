package pt.ulisboa.tecnico.sec.g19.hdscoin.client;


import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CheckAccountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.RegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class CheckAccount {
    // contains the protocol and host used and the initial port used
    public static final String SERVER_URL = "http://localhost:4570";

    public static void main(String[] args) throws CheckAccountException {
        String clientName;
        int numberOfServers;
        String password;

        // create options
        Options registerOptions = new Options();
        registerOptions.addOption("n", true, "Client name");
        registerOptions.addOption("ns", true, "Number of servers");
        registerOptions.addOption("pw", true, "Password");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(registerOptions, args);
        } catch (ParseException e) {
            throw new CheckAccountException("Can't check account, failed to interpret the arguments. " + e);
        }

        if (cmd.hasOption("n") && !cmd.getOptionValue("n").trim().equals("")) {
            clientName = cmd.getOptionValue("n");
        } else {
            usage(registerOptions);
            throw new CheckAccountException("Can't check account, client name is missing.");
        }
        if (cmd.hasOption("ns") && !cmd.getOptionValue("ns").trim().equals("")) {
            numberOfServers = Integer.parseInt (cmd.getOptionValue("ns"));
        } else {
            usage(registerOptions);
            throw new CheckAccountException ("Can't check account, number of servers available is missing.");
        }
        if (cmd.hasOption("pw") && !cmd.getOptionValue("pw").trim().equals("")) {
            password = cmd.getOptionValue("pw");
        } else {
            usage(registerOptions);
            throw new CheckAccountException ("Can't check account, number of servers available is missing.");
        }

        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\common";
        String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
        Path path = Paths.get (filepath).normalize();

        try {
            KeyStore keyStore = Utils.initKeyStore (path.toString ());
            ECPublicKey clientPublicKey = Utils.loadPublicKeyFromKeyStore (keyStore, clientName);
            ECPrivateKey clientPrivateKey = Utils.loadPrivateKeyFromKeyStore (path.toString (), clientName, password);

            IClient client = new Client(new URL(SERVER_URL), numberOfServers, path.toString ());
            Serialization.CheckAccountResponse result = client.checkAccount(clientPublicKey, clientPrivateKey);
            System.out.println("Balance: " + result.balance);
            if(result.pendingTransactions.size() > 0) {
                System.out.println("Pending incoming transactions:");
                for (Serialization.Transaction tx : result.pendingTransactions) {
                    System.out.println("  Signature: " + tx.signature);
                    System.out.printf("  Amount: %d from %s\n", tx.amount, tx.source);
                    System.out.println("--------");
                }
            } else {
                System.out.println("No pending incoming transactions");
            }

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new CheckAccountException("Failed to check the account of the public key provided. " + e);
        } catch (RegisterException e) {
            e.printStackTrace ();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace ();
        } catch (KeyException e) {
            e.printStackTrace ();
        }

    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("CheckAccount", options);
    }

}
