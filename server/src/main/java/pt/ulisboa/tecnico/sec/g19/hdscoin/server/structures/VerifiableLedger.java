package pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures;


import com.fasterxml.jackson.annotation.JsonIgnore;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Signable;

import java.util.List;


public class VerifiableLedger implements Hashable {
    private List<Serialization.Transaction> transactions;

    public VerifiableLedger(List<Serialization.Transaction> transactions) {
        this.transactions = transactions;
    }

    public List<Serialization.Transaction> getTransactions () {
        return this.transactions;
    }

    @Override public String getHashable () {
        StringBuilder hashable = new StringBuilder ();
        for (Serialization.Transaction tx : transactions) {
            hashable.append (tx.getSignable ());    // get signable is used because it would retrieve the same information as a getHashable on a transaction
        }
        return hashable.toString ();
    }
}
