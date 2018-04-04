package pt.ulisboa.tecnico.sec.g19.hdscoin.client;


import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.KeyGenerationException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collection;


@RunWith(Parameterized.class)
public class GenerateKeyPairTest {
    enum Type {INVALID_COMMAND_LINE_ARGS, VALID_COMMAND_LINE_ARGS }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { Type.INVALID_COMMAND_LINE_ARGS, "", ""}, { Type.INVALID_COMMAND_LINE_ARGS, " ", " "},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", "   "}, { Type.INVALID_COMMAND_LINE_ARGS, "-n", ""},
                { Type.INVALID_COMMAND_LINE_ARGS, "-abc", "CLIENT_TEST"},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", null },

                { Type.VALID_COMMAND_LINE_ARGS, "-n", "null" }, { Type.VALID_COMMAND_LINE_ARGS, "-n", "1" },
                { Type.VALID_COMMAND_LINE_ARGS, "-n", "CLIENT_TEST" }
        });
    }

    private Type type;
    private String flag;
    private String value;

    public GenerateKeyPairTest (Type type, String flag, String value) {
        this.flag = flag;
        this.value = value;
        this.type = type;
    }


    @Test (expected = KeyGenerationException.class)
    public void testMainInvalidArguments () throws KeyGenerationException {
        Assume.assumeTrue(type == Type.INVALID_COMMAND_LINE_ARGS);
        GenerateKeyPair.main(new String[] {flag, value});
    }

    @Test
    public void testMainValidArguments () throws KeyGenerationException {
        Assume.assumeTrue(type == Type.VALID_COMMAND_LINE_ARGS);
        GenerateKeyPair.main(new String[] {flag, value});
    }

    // check if the file with the keys was create
    @Test
    public void testMainCheckFileExists () throws KeyGenerationException {
        Assume.assumeTrue(type == Type.VALID_COMMAND_LINE_ARGS);
        GenerateKeyPair.main(new String[] {flag, value});
        // compose path
        String root = System.getProperty("user.dir");
        String filepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\";
        Path path = Paths.get (filepath).normalize();

        File file = new File (path.toString());
        Assert.assertTrue(file.exists());
    }

    @Test
    public void testMainCheckFileContainsKeys () throws KeyGenerationException, KeyException, IOException {
        Assume.assumeTrue(type == Type.VALID_COMMAND_LINE_ARGS);
        GenerateKeyPair.main(new String[] {flag, value});

        String root = System.getProperty("user.dir");
        String filepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + value + ".keys";
        Path path = Paths.get (filepath).normalize();

        ECPrivateKey privateKey = Utils.readPrivateKeyFromFile (path.toString());
        ECPublicKey publicKey = Utils.readPublicKeyFromFile (path.toString());

        Assert.assertNotEquals (privateKey, null);
        Assert.assertNotEquals (publicKey, null);
        Assert.assertNotEquals (publicKey, "");
        Assert.assertNotEquals (privateKey, "");
        Assert.assertEquals(publicKey.getAlgorithm(), "EC");    // elliptic curves
        Assert.assertEquals(privateKey.getAlgorithm(), "EC");
    }

    //@AfterClass
    public static void clean () {
        // destroy all the key files present on the keys directory.
        String root = System.getProperty("user.dir");
        String filepath = "\\src\\main\\java\\pt\\ulisboa\\tecnico\\sec\\g19\\hdscoin\\client\\keys";
        File dir = new File(root + filepath);
        if (dir.isDirectory()) {
            File files[] = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    file.delete ();
                }
            }
        }
    }
}
