package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;


public class Main {

    
    public static void main(String[] args) throws FailedToLoadKeysException {
        // fetch all relevant command line arguments
        String serverName = args[0];
        int port = Integer.parseInt (args[1]);
        int numberOfServers = Integer.parseInt (args[2]);
        String password = args[3];

        new Server("http://localhost:4570", serverName, port, numberOfServers, password).ignite();
    }
}
