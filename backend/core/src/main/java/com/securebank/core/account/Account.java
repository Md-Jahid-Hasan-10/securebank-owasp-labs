package com.securebank.core.account;

import java.math.BigDecimal;

/**
 * A customer bank account.
 */
public class Account {

    private Long id;
    private Long userId;
    private String accountNumber;
    private String sortCode;
    private BigDecimal balance;
    private String currency;

    public Account() {
    }

    public Account(Long id, Long userId, String accountNumber, String sortCode,
                   BigDecimal balance, String currency) {
        this.id = id;
        this.userId = userId;
        this.accountNumber = accountNumber;
        this.sortCode = sortCode;
        this.balance = balance;
        this.currency = currency;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getAccountNumber() {
        return accountNumber;
    }

    public void setAccountNumber(String accountNumber) {
        this.accountNumber = accountNumber;
    }

    public String getSortCode() {
        return sortCode;
    }

    public void setSortCode(String sortCode) {
        this.sortCode = sortCode;
    }

    public BigDecimal getBalance() {
        return balance;
    }

    public void setBalance(BigDecimal balance) {
        this.balance = balance;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }
}
