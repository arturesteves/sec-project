package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.KeyGenerationException;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.KeyPair;


public class GenerateKeyPair {
    public static final String ENTITY = "SERVER";

    public static void main(String[] args) throws KeyGenerationException {
        String serverName;

        // create options
        Options options = new Options ();
        options.addOption ("n", true, "Name of the server");

        CommandLineParser parser = new BasicParser ();
        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("n") && !cmd.getOptionValue("n").trim().equals("")) {
                serverName = cmd.getOptionValue("n");
            } else {
                usage (options);
                throw new KeyGenerationException("Failed to generate a key pair. Missing the -n option.");
            }
            String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\server";
            // create path and normalize it
            String filepath = root + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + serverName + ".keys";
            Path path = Paths.get (filepath).normalize();

            KeyPair keyPair = Utils.generateKeyPair ();
            Utils.writeKeyPairToFile (path.toString(), keyPair);

            // everything ok
            System.out.println();
            System.out.println("-------------------------------------");
            System.out.println("---Key Pair Generated with Success---");
            System.out.println("---Generated at: " + path.toString());
            System.out.println("-------------------------------------");

        } catch (ParseException | KeyException | IOException e) {
            throw new KeyGenerationException("Failed to generate a key pair. " + e.getMessage(), e);
        }

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "GenerateKeyPair", options);
    }

}
