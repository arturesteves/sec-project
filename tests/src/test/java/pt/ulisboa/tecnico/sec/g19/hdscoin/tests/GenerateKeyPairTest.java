package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.junit.Assert;
import org.junit.Test;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.KeyGenerationException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.GenerateKeyPair;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Main;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class GenerateKeyPairTest {


    @Test (expected = KeyGenerationException.class)
    public void testMainInvalidArguments () throws KeyGenerationException {
        GenerateKeyPair.main(new String[] {""});
    }

    @Test
    public void testMainValidArguments () throws KeyGenerationException {
        GenerateKeyPair.main(new String[] {"-n", "SERVER_KEYS_TEST"});
    }
/*


    // check if the file with the keys was create
    @Test
    public void testMainCheckFileExists () throws KeyGenerationException {
        String serverID = "SERVER_KEYS_TEST";
        GenerateKeyPair.main(new String[] {"-n", serverID});
        // compose path
        String root = System.getProperty("user.dir");
        String filepath = root + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + serverID + ".keys";
        Path path = Paths.get (filepath).normalize();

        File file = new File (path.toString());
        Assert.assertTrue(file.exists());
    }

    @Test
    public void testMainCheckFileContainsKeys () throws KeyGenerationException, KeyException, IOException {
        String serverID = "SERVER_KEYS_TEST";
        GenerateKeyPair.main(new String[] {"-n", serverID});
        // compose path
        String root = System.getProperty("user.dir");
        String filename = root + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + serverID + ".keys";
        Path path = Paths.get (filename).normalize();

        ECPrivateKey privateKey = Utils.readPrivateKeyFromFile (path.toString());
        ECPublicKey publicKey = Utils.readPublicKeyFromFile (path.toString());

        Assert.assertNotEquals (privateKey, null);
        Assert.assertNotEquals (publicKey, null);
        Assert.assertNotEquals (publicKey, "");
        Assert.assertNotEquals (publicKey, "");
        Assert.assertEquals(privateKey.getAlgorithm(), "EC");
    }
*/
}

