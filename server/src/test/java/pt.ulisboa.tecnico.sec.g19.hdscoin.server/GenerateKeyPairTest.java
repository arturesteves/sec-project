package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import org.junit.Assert;
import org.junit.Test;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.CantGenerateKeysException;

import java.io.File;
import java.io.IOException;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class GenerateKeyPairTest {

    @Test(expected = CantGenerateKeysException.class)
    public void testMainInvalidArguments () throws CantGenerateKeysException {
        GenerateKeyPair.main(new String[] {""});
    }

    @Test
    public void testMainValidArguments () throws CantGenerateKeysException {
        GenerateKeyPair.main(new String[] {"-n", "SERVER_KEYS_TEST"});
    }

    // check if the file with the keys was create
    @Test
    public void testMainCheckFileExists () throws CantGenerateKeysException {
        String serverID = "SERVER_KEYS_TEST";
        GenerateKeyPair.main(new String[] {"-n", serverID});
        String root = System.getProperty("user.dir");
        String filepath = "/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/server/keys/" + serverID + ".keys";

        File file = new File (root + filepath);
        Assert.assertTrue(file.exists());
    }

    @Test
    public void testMainCheckFileContainsKeys () throws CantGenerateKeysException, KeyException, IOException {
        String serverID = "SERVER_KEYS_TEST";
        GenerateKeyPair.main(new String[] {"-n", serverID});
        //String root = System.getProperty("user.dir");
        String filepath = "/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/server/keys/" + serverID + ".keys";

        ECPrivateKey privateKey = Utils.readPrivateKeyFromFile (filepath);
        ECPublicKey publicKey = Utils.readPublicKeyFromFile (filepath);

        Assert.assertNotEquals (privateKey, null);
        Assert.assertNotEquals (publicKey, null);
        Assert.assertNotEquals (publicKey, "");
        Assert.assertNotEquals (publicKey, "");
        Assert.assertEquals(privateKey.getAlgorithm(), "EC");
    }
}
