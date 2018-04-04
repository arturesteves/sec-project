package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;

import java.util.List;

public class CheckAccountResult {
    public int balance;
    public List<Serialization.Transaction> pendingTransactions;

    public CheckAccountResult(int balance, List<Serialization.Transaction> pendingTransactions) {
        this.balance = balance;
        this.pendingTransactions = pendingTransactions;
    }
}
