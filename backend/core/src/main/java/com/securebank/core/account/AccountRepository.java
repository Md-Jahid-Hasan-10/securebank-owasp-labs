package com.securebank.core.account;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class AccountRepository {

    private static final RowMapper<Account> MAPPER = (rs, rowNum) -> new Account(
            rs.getLong("id"),
            rs.getLong("user_id"),
            rs.getString("account_number"),
            rs.getString("sort_code"),
            rs.getBigDecimal("balance"),
            rs.getString("currency"));

    private final JdbcTemplate jdbc;

    public AccountRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<Account> findById(Long id) {
        List<Account> found = jdbc.query(
                "SELECT id, user_id, account_number, sort_code, balance, currency "
                        + "FROM accounts WHERE id = ?",
                MAPPER, id);
        return found.stream().findFirst();
    }

    public List<Account> findByUserId(Long userId) {
        return jdbc.query(
                "SELECT id, user_id, account_number, sort_code, balance, currency "
                        + "FROM accounts WHERE user_id = ? ORDER BY id",
                MAPPER, userId);
    }

    public List<Account> findAll() {
        return jdbc.query(
                "SELECT id, user_id, account_number, sort_code, balance, currency "
                        + "FROM accounts ORDER BY id",
                MAPPER);
    }

    public void updateBalance(Long accountId, BigDecimal balance) {
        jdbc.update("UPDATE accounts SET balance = ? WHERE id = ?", balance, accountId);
    }
}
