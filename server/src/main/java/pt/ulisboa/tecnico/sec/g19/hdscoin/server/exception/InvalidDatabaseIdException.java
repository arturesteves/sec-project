package pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception;

public class InvalidDatabaseIdException extends Exception {

    public InvalidDatabaseIdException(String message, int id) {
        super(message + " ID: " + id);
    }
}
