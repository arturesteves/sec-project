package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantRegisterException;
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

    public static final String SERVER_URL = "http://localhost:4567";
    public static final String SERVER_PUBLIC_KEY_BASE_64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/GJhA+8icaML6/zYhJ1QY4oEbhzUqjzJmECK5dTJ2mRpS4Vsks0Zy52Q8HiNGQvDpO8wLr/a5X0yTV+Sj1vThQ==";

    public static void main(String[] args) throws CantRegisterException {
        String clientName;
        int amount;

        // create options
        Options registerOptions = new Options();
        registerOptions.addOption("n", true, "Client name");
        registerOptions.addOption("a", true, "Amount to initialize the account");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(registerOptions, args);
        } catch (ParseException e) {
            e.printStackTrace();
            throw new CantRegisterException("Can't register, failed to interpreter the arguments. " + e, e);
        }

        if (cmd.hasOption("n") && !cmd.getOptionValue("n").trim().equals("")) {
            clientName = cmd.getOptionValue("n");
        } else {
            usage(registerOptions);
            throw new CantRegisterException("Can't register, client name is missing.");
        }
        if (cmd.hasOption("a") && !cmd.getOptionValue("a").trim().equals("")) {
            try {
                amount = Integer.parseInt(cmd.getOptionValue("a"));
            } catch (NullPointerException | NumberFormatException e) {
                throw new CantRegisterException("Can't register, the amount is invalid. " + e, e);
            }
        } else {
            usage(registerOptions);
            throw new CantRegisterException("Can't register, amount is missing.");
        }

        String root = System.getProperty("user.dir");
        String filepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + clientName + ".keys";
        Path path = Paths.get(filepath).normalize(); // create path and normalize it

        try {

            ECPublicKey clientPublickey = Utils.readPublicKeyFromFile(path.toString());
            ECPrivateKey clientPrivateKey = Utils.readPrivateKeyFromFile(path.toString());
            ECPublicKey serverPublicKey = Serialization.base64toPublicKey(SERVER_PUBLIC_KEY_BASE_64);

            IClient client = new Client(new URL(SERVER_URL), serverPublicKey);
            client.register(clientPublickey, clientPrivateKey, amount);

        } catch (KeyException | IOException e) {
            throw new CantRegisterException("Failed to register. " + e, e);
        } catch (Exception e) {
            throw new CantRegisterException("Failed to register, due to an unexpected error. " + e, e);
        }

    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("Register", options);
    }

}