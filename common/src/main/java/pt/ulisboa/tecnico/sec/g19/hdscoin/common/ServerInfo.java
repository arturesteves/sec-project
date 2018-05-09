package pt.ulisboa.tecnico.sec.g19.hdscoin.common;


import com.fasterxml.jackson.annotation.JsonIgnore;

import java.net.URL;
import java.security.interfaces.ECPublicKey;


public class ServerInfo implements Signable {
    public URL serverUrl;
    public String publicKeyBase64;

    public ServerInfo() {}
    public ServerInfo(URL serverUrl, String publicKeyBase64) {
        this.serverUrl = serverUrl;
        this.publicKeyBase64 = publicKeyBase64;
    }

    @Override
    @JsonIgnore
    public String getSignable () {
        return serverUrl.toString() + publicKeyBase64;
    }

    @Override public String toString () {
        return "ServerInfo{" + "serverUrl=" + serverUrl + ", publicKeyBase64='" + publicKeyBase64 + '\'' + '}';
    }
}

