package pt.ulisboa.tecnico.sec.g19.hdscoin.client;


import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.AuditException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.interfaces.ECPublicKey;
import java.util.List;

public class Audit {
    public static final String SERVER_URL = "http://localhost:4570";

    public static void main(String[] args) throws AuditException {
        String clientName;
        String serverName;

        // create options
        Options registerOptions = new Options();
        registerOptions.addOption("n", true, "Client name");
        registerOptions.addOption("s", true, "Server name");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(registerOptions, args);
        } catch (ParseException e) {
            throw new AuditException("Can't audit account, failed to interpret the arguments. " + e);
        }

        if (cmd.hasOption("n") && !cmd.getOptionValue("n").trim().equals("")) {
            clientName = cmd.getOptionValue("n");
        } else {
            usage(registerOptions);
            throw new AuditException("Can't audit account, client name is missing.");
        }
        if (cmd.hasOption("s") && !cmd.getOptionValue("s").trim().equals("")) {
            serverName = cmd.getOptionValue("s");
        } else {
            usage(registerOptions);
            throw new AuditException("Can't audit account, server name is missing.");
        }

        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\client";


        // This is more or less a simulation of a CA
        // Note that we could obtain the private keys here, but we won't do it (we assume that if a CA was
        // in place, we'd obtain the public keys from it, and not from a file).
        String clientKeyFilepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + clientName + ".keys";
        Path clientKeyPath = Paths.get(clientKeyFilepath).normalize(); // create path and normalize it
        String serverKeyFilepath = root + "\\..\\server\\" + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + serverName + ".keys";
        Path serverKeyPath = Paths.get(serverKeyFilepath).normalize(); // create path and normalize it

        try {
            ECPublicKey clientPublickey = Utils.readPublicKeyFromFile(clientKeyPath.toString());
            ECPublicKey serverPublicKey = Utils.readPublicKeyFromFile(serverKeyPath.toString());

            IClient client = new Client(new URL(SERVER_URL), serverPublicKey);
            List<Serialization.Transaction> transactions = client.audit(clientPublickey);

            System.out.println("Transactions:");
            for (Serialization.Transaction tx : transactions) {
                System.out.println("  Signature: " + tx.signature);
                if(tx.isSend) {
                    System.out.printf("  Sent: %d to %s\n", tx.amount, tx.target);
                } else {
                    if(tx.source.equals(tx.target)) {
                        System.out.printf("  Account opened with %d\n", tx.amount);
                    } else {
                        System.out.printf("  Received: %d from %s\n", tx.amount, tx.source);
                    }
                }
                System.out.println("--------");
            }

        } catch (KeyException | IOException e) {
            throw new AuditException("Failed to audit the account of the public key provided. " + e);
        }

    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("Audit", options);
    }

}
