package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.CantGenerateKeysException;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;


public class GenerateKeyPair {
    public static final String ENTITY = "CLIENT";
    public static final String FILE_PATH = "/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/client/keys";

    public static void main(String[] args) throws ParseException, CantGenerateKeysException, KeyException, IOException {
        String clientName;

        // create options
        Options options = new Options ();
        options.addOption ("n", true, "Name of the client");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = parser.parse(options, args);

        if (cmd.hasOption("n")) {
            clientName = cmd.getOptionValue("n");
        } else {
            usage (options);
            throw new RuntimeException("\nMissing the -n option.\n");
        }

        KeyPair keyPair = Utils.generateKeyPair ();
        Utils.writeKeyPairToFile (FILE_PATH + "/" + clientName + ".keys", keyPair);

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "GenerateKeyPair", options);
    }
}
