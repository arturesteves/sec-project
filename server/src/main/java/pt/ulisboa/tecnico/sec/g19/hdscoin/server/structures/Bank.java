package pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidDatabaseId;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.NonExistenceLedgerException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;


public final class Bank {

    private int id;
    private List<Ledger> ledgers;


    public Bank (int id) {
    	this.id = id;
    	this.ledgers = new ArrayList<>();
    }

    public Bank () {
    	this (-1);
    }


    public int getID () {
        return this.id;
    }

    public void setId (int id) throws InvalidDatabaseId{
        if (id > 0) {
            this.id = id;
        }
        throw new InvalidDatabaseId ("The id has to be a positive integer number.", id);
    }

    public void addLedger (Ledger ledger) throws InvalidLedgerException {
    	if (ledger == null) {
    		throw new InvalidLedgerException ("The ledger can't be null.");
    	}
    	this.ledgers.add (ledger);
    }

    public Ledger getLedger (ECPublicKey key) throws NonExistenceLedgerException{
    	for (Ledger ledger : this.ledgers) {
    		if (ledger.getPublicKey () == key ) {
    			return ledger;
    		}
    	}
    	throw new NonExistenceLedgerException ("There is no corresponding ledger associated to the key provided.", key);
    }

}