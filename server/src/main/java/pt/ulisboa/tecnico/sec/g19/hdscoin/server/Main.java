package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;


public class Main {

    
    public static void main(String[] args) throws FailedToLoadKeysException {
        new Server("http://localhost:4570").run(args);
    }
}
