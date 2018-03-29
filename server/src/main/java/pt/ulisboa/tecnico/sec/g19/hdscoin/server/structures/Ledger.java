package pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures;

import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.*;

import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.interfaces.ECPublicKey;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;


public final class Ledger {

    private int id;
    private ECPublicKey publicKey;    // can't change
    private int amount;

    private Ledger(int id, ECPublicKey publicKey, int amount) {
        this.publicKey = publicKey;
        this.amount = amount;
        this.id = id;
    }

    public Ledger(Connection connection, ECPublicKey publicKey, int amount) throws SQLException, InvalidKeyException, InvalidAmountException, InvalidLedgerException {
        this(-1, publicKey, amount);
        if (publicKey == null) {
            throw new InvalidKeyException("Null key when trying to initialize a ledger.");
        }

        // check if a ledger with this public key already exists. If yes, this ledger can't be created
        try {
            load(connection, publicKey);
            throw new InvalidLedgerException("A ledger with this public key already exists");
        } catch(MissingLedgerException ex) {
            // it's ok, go on
        } catch (KeyException e) {
            throw new InvalidKeyException(e);
        }

        if (amount < 1) {
            throw new InvalidAmountException("Insufficient amount to setup a ledger.", amount);
        }
        // generate new ID for ledger based on highest ID in the database
        try {
            setId(getNextId(connection));
        } catch(InvalidDatabaseIdException ex) {
            // say what? getNextId always returns positive IDs
        }
    }

    public int getId() {
        return this.id;
    }

    private void setId(int id) throws InvalidDatabaseIdException {
        if (id > 0) {
            this.id = id;
        }
        throw new InvalidDatabaseIdException("The id has to be a positive integer number.", id);
    }

    public ECPublicKey getPublicKey() {
        return this.publicKey;
    }

    public int getAmount() {
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
        prepStmt.setInt(3, getAmount());
        prepStmt.executeUpdate();
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
            throw new MissingLedgerException("A ledger with the specified public key was not found");
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