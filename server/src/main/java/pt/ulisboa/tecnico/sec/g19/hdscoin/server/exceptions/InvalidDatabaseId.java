package pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions;

public class InvalidDatabaseId extends Exception {

    public InvalidDatabaseId (String message, int id) {
        super (message + " ID: " + id);
    }
}
