package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.ReceiveAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.RegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class Register {
    // contains the protocol and host used and the initial port used
    public static final String SERVER_URL = "http://localhost:4570";

    public static void main(String[] args) throws RegisterException {
        String clientName;
        int amount;
        int numberOfServers;
        String password;

        // create options
        Options registerOptions = new Options();
        registerOptions.addOption("n", true, "Client name");
        registerOptions.addOption("a", true, "Amount to initialize the account");
        registerOptions.addOption ("ns", true, "Number of servers");
        registerOptions.addOption ("pw", true, "Password to access to obtain the private key from the key store");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(registerOptions, args);
        } catch (ParseException e) {
            e.printStackTrace();
            throw new RegisterException("Can't register, failed to interpret the arguments. " + e, e);
        }

        if (cmd.hasOption("n") && !cmd.getOptionValue("n").trim().equals("")) {
            clientName = cmd.getOptionValue("n");
        } else {
            usage(registerOptions);
            throw new RegisterException("Can't register, client name is missing.");
        }
        if (cmd.hasOption("a") && !cmd.getOptionValue("a").trim().equals("")) {
            try {
                amount = Integer.parseInt(cmd.getOptionValue("a"));
            } catch (NullPointerException | NumberFormatException e) {
                throw new RegisterException("Can't register, the amount is invalid. " + e, e);
            }
        } else {
            usage(registerOptions);
            throw new RegisterException("Can't register, amount is missing.");
        }
        if (cmd.hasOption ("ns") && !cmd.getOptionValue ("ns").trim ().equals ("")) {
            numberOfServers = Integer.parseInt (cmd.getOptionValue ("ns"));
        } else {
            usage (registerOptions);
            throw new RegisterException ("Can't register, number of servers available is missing.");
        }
        if (cmd.hasOption ("pw") && !cmd.getOptionValue ("pw").trim ().equals ("")) {
            password = cmd.getOptionValue ("pw");
        } else {
            usage (registerOptions);
            throw new RegisterException ("Failed to register. Missing the -pw option.");
        }

        String root = Paths.get (System.getProperty ("user.dir")).getParent ().toString () + "\\common";
        String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
        Path path = Paths.get (filepath).normalize ();

        try {
            KeyStore keyStore = Utils.initKeyStore (path.toString ());
            ECPublicKey clientPublicKey = Utils.loadPublicKeyFromKeyStore (keyStore, clientName);
            ECPrivateKey clientPrivateKey = Utils.loadPrivateKeyFromKeyStore (path.toString (), clientName, password);

            IClient client = new Client(new URL(SERVER_URL), numberOfServers, path.toString ());
            client.register(clientPublicKey, clientPrivateKey, amount);
        } catch (IOException e) {
            throw new RegisterException("Failed to register. " + e, e);
        } catch (Exception e) {
            throw new RegisterException("Failed to register, due to an unexpected error. " + e, e);
        }

    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("Register", options);
    }

}