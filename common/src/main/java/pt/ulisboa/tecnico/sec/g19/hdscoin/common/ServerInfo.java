package pt.ulisboa.tecnico.sec.g19.hdscoin.common;


import java.net.URL;
import java.security.interfaces.ECPublicKey;


public class ServerInfo implements Signable {
    public URL serverUrl;
    public ECPublicKey publicKey;

    public ServerInfo(URL serverUrl, ECPublicKey publicKey) {
        this.serverUrl = serverUrl;
        this.publicKey = publicKey;
    }

    @Override public String getSignable () {
        return serverUrl.toString() + publicKey;
    }
}
