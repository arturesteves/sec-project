package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import static org.mockito.Mockito.*;
import com.github.paweladamski.httpclientmock.HttpClientMock;
import org.eclipse.jetty.client.HttpClient;
//import org.apache.http.client.HttpClient;

import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantRegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.CantGenerateKeysException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.CantGenerateSignatureException;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.util.Arrays;
import java.util.Collection;


//@RunWith(Parameterized.class)
public class RegisterTest {

    //@Mock
    private HttpClient mockHttpClient;

    //private static HttpClientMock httpClientMock;

    /*
    enum Type {INVALID_COMMAND_LINE_ARGS, VALID_COMMAND_LINE_ARGS }
    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                { Type.INVALID_COMMAND_LINE_ARGS, "", ""},      { Type.INVALID_COMMAND_LINE_ARGS, " ", " "},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", "   "}, { Type.INVALID_COMMAND_LINE_ARGS, "-abc", "CLIENT_TEST"},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", null }, { Type.INVALID_COMMAND_LINE_ARGS, "-n", "Client_1"},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", "C1", "-a", "abc"},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", "C1", "-a", null},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", "C1", "-a", ""},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", "C1", "-a", "  "},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", "C1", "-a", "0"},
                { Type.INVALID_COMMAND_LINE_ARGS, "-n", "C1", "-a", "-1"},

                { Type.VALID_COMMAND_LINE_ARGS, "-n", "C1", "-a", "20"},
                { Type.VALID_COMMAND_LINE_ARGS, "-n", "C1", "-a", "0.1"},
        });
    }

    private Type type;
    private String flagName;
    private String name;
    private String flagAmount;
    private String amount;
    public RegisterTest (Type type, String flagName, String name, String flagAmount, String amount) {
        this.type = type;
        this.flagName = flagName;
        this.name = name;
        this.flagAmount = flagAmount;
        this.amount = amount;
    }

    @Test (expected = CantRegisterException.class)
    public void testRegisterInvalidArguments () throws CantRegisterException {
        Assume.assumeTrue(type == Type.INVALID_COMMAND_LINE_ARGS);
        Register.main(new String[] {flagName, name, flagAmount, amount});
    }

    @Test (expected = CantRegisterException.class)
    public void testRegisterWithNoGeneratedKey () throws CantRegisterException {
        // no key was generated under the name Cli_1
        Register.main(new String[] {"-n", "Cli_1", "-a", "10"});
    }

    @Test
    public void testRegisterValidArguments () throws CantRegisterException, CantGenerateKeysException {
        Assume.assumeTrue(type == Type.INVALID_COMMAND_LINE_ARGS);
        GenerateKeyPair.main(new String[] {flagName, name});    // needs to generate a key pair first
        Register.main(new String[] {flagName, name, flagAmount, amount});
    }
*/


    // Ficheiro Client_1.keys contem estas chaves
    // client private key 64: MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgDlXAfPhByP9XqYdVC3yASY/6yZYQfl/hiSijZJBBzHSgCgYIKoZIzj0DAQehRANCAARtr98LHUDeOfTBru26kYGgI+om9e9sLKq1oWa9dleShSSWtz2MJ6fK95RqaELRkfc17WuhlYv4xMJn2Wk4yEed
    // client public key b64: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEba/fCx1A3jn0wa7tupGBoCPqJvXvbCyqtaFmvXZXkoUklrc9jCenyveUamhC0ZH3Ne1roZWL+MTCZ9lpOMhHnQ==
    // client amount: 10
    // client nonce: L!+7>i?]ebwJR3^e*i?<
    // mensage signature for register (public key + amount + nonce): MEQCIGWVj8dH6aeAqvUOgUnHhXRWDBgLYr5Ub57mm6AqGvaGAiAdNMZfyWkuGNpAjFiNhGX+voSN7MQ29d0hs0rKsSo/ZQ==

    @Test
    public void testSimple () throws CantRegisterException {
        System.err.println("TEST SIMPLE");
        Register.main(new String[] {"-n", "Client_1", "-a", "10"});
        System.out.println("END TEST SIMPLE");
        //todo: criar forma de alterar as mensagens, pq agora da jeito usar um nonce predefinido.
            // isto depois tambem ajuda para simular os ataques.
    }

    @Test (expected = CantRegisterException.class)
    public void testSimple2 () throws CantRegisterException {
        System.err.println("TEST SIMPLE 2");
        Register.main(new String[] {"-n", "Client_", "-a", "10"});
        System.out.println("END TEST SIMPLE 2");
    }

    // statusCode: 200,
    // status: "SUCCESS"
    // nonce: L!+7>i?]ebwJR3^e*i?<
    // server signature : MEUCICP0JI/bly4aHZASl9/pdpCAKMjKg6VT4hCxc5/l+YJuAiEAm4GJx4NdDYwQMTPTv8DrfuVrc4oZWGLqdx/34QGSWag=
    @Before
    public void setup () throws KeyException, CantGenerateSignatureException {
        // install dependency mockito
        //mockHttpClient = mock(HttpClient.class);    // confirmar
        //MockitoAnnotations.initMocks(RegisterTest.class); // check if need .class
        //when(mockHttpClient.execute(any())).thenReturn(/*stub json*/);

        /*
        // esqueçer isto, e preciso configurar em algum lado (desconhecido) onde e que a classe deve usar este httpclient e nao o default1
        httpClientMock = new HttpClientMock("http://example.com:4567");
        // Setup register mock service
        httpClientMock
                .onPost("/register")
                // 1st request returns OK
                .doReturnJSON("{\n" +
                        "    \"statusCode\": 200,\n" +
                        "    \"status\": \"SUCCESS\",\n" +
                        "    \"nonce\": \"L!+7>i?]ebwJR3^e*i?<\"\n" +
                        "}")
                .withHeader("SIGNATURE", "MEQCIGWVj8dH6aeAqvUOgUnHhXRWDBgLYr5Ub57mm6AqGvaGAiAdNMZfyWkuGNpAjFiNhGX+voSN7MQ29d0hs0rKsSo/ZQ==")
                .withStatus(200)
                // 2nd request returns ERROR with clients fault
                .doReturnJSON("{\n" +
                        "    \"statusCode\": 400,\n" +
                        "    \"status\": \"ERROR_INVALID_LEDGER\",\n" +
                        "    \"nonce\": \"L!+7>i?]ebwJR3^e*i?<\"\n" +
                        "}")
                .withHeader("SIGNATURE", "")
                .withStatus(400)
                // 2nd request returns ERROR with servers fault
                .doReturnJSON("{\n" +
                        "    \"statusCode\": 400,\n" +
                        "    \"status\": \"ERROR_INVALID_LEDGER\",\n" +
                        "    \"nonce\": \"L!+7>i?]ebwJR3^e*i?<\"\n" +
                        "}") // 2nd request returns ERROR ...
                .withHeader("SIGNATURE", "")
                .withStatus(500);
*/
        /*
        String pk = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/oPH6wF/95MfKaddTaH9vNthLmCHV86x2x+KTVghgjOzQEliExrpxb/McrO86JLGRREJVinKO/6QaWYXz0WzzA==";
        String p = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgEiqXHRtwcJz0zlfQ5RtfMhKTCZMEImKKieUJcD9MQPygCgYIKoZIzj0DAQehRANCAAQLTQWfpfICeLo/Mx9zeaM6pqEy8hTjqHKyXVfHVXe9Yivuf9h+EYeyv3pxH9g+ssbR9yy64WsmSYEypVgin+oJ";
        double a = 10;
        System.err.println("SIGNATURE: " + Utils.generateSignature(pk + Double.toString(a), Serialization.base64toPrivateKey(p)));
        */

        //public int statusCode = -1;
        //public StatusMessage status;
        //public String nonce;

        //HttpClientMock httpClientMock = new httpClientMock();
        //httpClientMocknew = new HttpClientMock("http://example.com:8080");
        //httpClientMock.onGet("/login?user=john").doReturnJSON("{permission:1}");

    }
    //@AfterClass
    public static void clean () {
        // shutdown web server

        // destroy all the key files present on the keys directory.
        // compose path
        String root = System.getProperty("user.dir");
        String filepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys";
        Path path = Paths.get (filepath).normalize();

        File dir = new File(filepath.toString());
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
