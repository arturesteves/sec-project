package pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures;

import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.*;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;


public final class Ledger {
    private final static Logger log = Logger.getLogger (Ledger.class.getName ());

    private int id;
    private ECPublicKey publicKey;    // can't change
    private double amount;

    private Ledger(int id, ECPublicKey publicKey, double amount) {
        Utils.initLogger (log);
        this.publicKey = publicKey;
        this.amount = amount;
        this.id = id;
    }

    public Ledger(Connection connection, ECPublicKey publicKey, double amount) throws KeyException, SQLException, InvalidKeyException, InvalidAmountException, InvalidLedgerException {
        this(-1, publicKey, amount);
        if (publicKey == null) {
            log.log (Level.WARNING, "Null key when trying to initialize a ledger.");
            throw new InvalidKeyException("Null key when trying to initialize a ledger.");
        }

        // check if a ledger with this public key already exists. If yes, this ledger can't be created
        try {
            load(connection, publicKey);
            log.log (Level.WARNING, "A ledger with this public key already exists.");
            throw new InvalidLedgerException("A ledger with this public key already exists.");
        } catch(MissingLedgerException ex) {
            // it's ok, go on
        } catch (KeyException e) {
            throw new InvalidKeyException(e);
        }

        if (amount < 1) {
            log.log (Level.WARNING, "Insufficient amount to setup a ledger.");
            throw new InvalidAmountException("Insufficient amount to setup a ledger.", amount);
        }
        // generate new ID for ledger based on highest ID in the database
        setId(getNextId(connection));

        // GENERATE 1st transaction (dummy, but required)
        generateFirstTransaction (connection);
        log.log (Level.INFO, "The first transaction was generated to the ledger with the following " +
                "public key base 64: " + Serialization.publicKeyToBase64 (publicKey));
    }

    public int getId() {
        return this.id;
    }

    private void setId(int id) {
        this.id = id;
    }

    public ECPublicKey getPublicKey() {
        return this.publicKey;
    }

    public double getAmount() {
        return this.amount;
    }

    public void setAmount(int amount) throws InvalidAmountException {
        if (amount >= 0) {
            this.amount = amount;
        }
        throw new InvalidAmountException("The balance of the ledger can't be negative.", amount);
    }

    public void persist(Connection connection) throws SQLException, KeyException {
        String stmt = "INSERT OR REPLACE INTO ledger (id, public_key, balance) VALUES (?, ?, ?)";

        PreparedStatement prepStmt = connection.prepareStatement(stmt);
        prepStmt.setInt(1, getId());
        prepStmt.setString(2, Serialization.publicKeyToBase64(getPublicKey()));
        prepStmt.setDouble(3, getAmount());
        prepStmt.executeUpdate();
        log.log (Level.INFO, "A ledger was persisted. Public key of that ledger: " + getPublicKey());
    }

    // useful for the audit
    public List<Transaction> getAllTransactions () {
        return null;
    }

    // useful for the check account
    // when im the source and the transactions are pending.
    public List<Transaction> getPendingTransactions (Connection connection, ECPublicKey publicKey) throws SQLException, KeyException, MissingLedgerException {
        String stmt = "SELECT * FROM tx AS t " +
                "JOIN ledger AS l ON t.ledger_id = l.id " +
                "WHERE l.public_key = ? " +
                "AND t.pending = 1";
        PreparedStatement prepStmt = connection.prepareStatement(stmt);
        prepStmt.setString(1, Serialization.publicKeyToBase64(publicKey));

        return Transaction.loadResults (connection, prepStmt);
    }


    private void generateFirstTransaction (Connection connection) {
        try {
            String base64PublicKey = Serialization.publicKeyToBase64 (this.publicKey);
            // values to hash a transaction, true: because is_send = true, and null because the previous hash is null
            String txValuesToHash = base64PublicKey + base64PublicKey + Boolean.toString(true) +
                    Double.toString (this.amount) + null;
            // hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hash = Arrays.toString(digest.digest(txValuesToHash.getBytes(StandardCharsets.UTF_8)));

            Transaction tx = new Transaction (connection, this, this, this.amount, Utils.randomNonce(),
                    hash, null, Transaction.EspecialTransactionType.FIRST);
            tx.setPending(false);   // is not pending

            tx.persist(connection);
            // persist a transaction

        } catch (NoSuchAlgorithmException | SQLException | KeyException | InvalidLedgerException | InvalidAmountException |
                InvalidValueException e) {

        }
    }

    public static Ledger load(Connection connection, int id) throws SQLException, KeyException, MissingLedgerException {
        String stmt = "SELECT * FROM ledger WHERE id = ?";
        PreparedStatement prepStmt = connection.prepareStatement(stmt);
        prepStmt.setInt(1, id);

        List<Ledger> results = loadResults(prepStmt);
        if(results.size() == 0) {
            throw new MissingLedgerException("A ledger with the specified ID was not found");
        }
        return results.get(0);
    }

    public static Ledger load(Connection connection, ECPublicKey pk) throws SQLException, KeyException, MissingLedgerException {
        String stmt = "SELECT * FROM ledger WHERE public_key = ?";
        PreparedStatement prepStmt = connection.prepareStatement(stmt);
        prepStmt.setString(1, Serialization.publicKeyToBase64(pk));

        List<Ledger> results = loadResults(prepStmt);
        if(results.size() == 0) {
            log.log (Level.WARNING, "A ledger with the specified public key was not found. Public Key: " + pk);
            throw new MissingLedgerException("A ledger with the specified public key was not found.");
        }
        return results.get(0);
    }

    public static List<Ledger> loadAll(Connection connection) throws SQLException, KeyException, MissingLedgerException {
        String stmt = "SELECT * FROM ledger";
        PreparedStatement prepStmt = connection.prepareStatement(stmt);

        return loadResults(prepStmt);
    }

    private static List<Ledger> loadResults(PreparedStatement prepStmt) throws SQLException, KeyException {
        List<Ledger> ret = new ArrayList<>();
        ResultSet results = prepStmt.executeQuery();
        while(results.next()) {
            int id = results.getInt(1);
            ECPublicKey pk = Serialization.base64toPublicKey(results.getString(2));
            int amount = results.getInt(3);
            ret.add(new Ledger(id, pk, amount));
        }
        return ret;
    }

    private static int getNextId(Connection connection) throws SQLException {
        int next = 0;
        Statement statement = connection.createStatement();
        ResultSet rs = statement.executeQuery("select max(id) from ledger");
        while(rs.next()) {
            next = rs.getInt(1) + 1;
        }
        return next;
    }
}