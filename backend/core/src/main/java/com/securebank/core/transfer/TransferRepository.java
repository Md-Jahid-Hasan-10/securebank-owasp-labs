package com.securebank.core.transfer;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class TransferRepository {

    private static final RowMapper<Transfer> MAPPER = (rs, rowNum) -> new Transfer(
            rs.getLong("id"),
            rs.getLong("from_account_id"),
            rs.getLong("to_account_id"),
            rs.getBigDecimal("amount"),
            rs.getString("note"),
            rs.getString("remark"),
            rs.getObject("created_at", OffsetDateTime.class));

    private final JdbcTemplate jdbc;

    public TransferRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<Transfer> findById(Long id) {
        List<Transfer> found = jdbc.query(
                "SELECT id, from_account_id, to_account_id, amount, note, remark, created_at "
                        + "FROM transfers WHERE id = ?",
                MAPPER, id);
        return found.stream().findFirst();
    }

    public List<Transfer> findByAccountId(Long accountId) {
        return jdbc.query(
                "SELECT id, from_account_id, to_account_id, amount, note, remark, created_at "
                        + "FROM transfers WHERE from_account_id = ? OR to_account_id = ? "
                        + "ORDER BY created_at DESC",
                MAPPER, accountId, accountId);
    }

    public List<Transfer> findAll() {
        return jdbc.query(
                "SELECT id, from_account_id, to_account_id, amount, note, remark, created_at "
                        + "FROM transfers ORDER BY id",
                MAPPER);
    }

    public Long insert(Long fromAccountId, Long toAccountId, java.math.BigDecimal amount,
                        String note) {
        org.springframework.jdbc.support.GeneratedKeyHolder keyHolder =
                new org.springframework.jdbc.support.GeneratedKeyHolder();
        jdbc.update(conn -> {
            var ps = conn.prepareStatement(
                    "INSERT INTO transfers (from_account_id, to_account_id, amount, note) "
                            + "VALUES (?, ?, ?, ?)",
                    new String[] { "id" });
            ps.setLong(1, fromAccountId);
            ps.setLong(2, toAccountId);
            ps.setBigDecimal(3, amount);
            ps.setString(4, note);
            return ps;
        }, keyHolder);
        return keyHolder.getKey().longValue();
    }

    public void updateRemark(Long id, String remark) {
        jdbc.update("UPDATE transfers SET remark = ? WHERE id = ?", remark, id);
    }
}
