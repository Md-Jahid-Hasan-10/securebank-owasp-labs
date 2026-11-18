package com.securebank.core.user;

/**
 * A banking customer or staff member.
 *
 * <p>The {@code passwordHash} column deliberately holds an <b>unsalted MD5</b> hex digest.
 * See {@link PasswordService} and Lab 7 (A04).</p>
 */
public class User {

    private Long id;
    private String username;
    private String email;
    private String passwordHash;
    private String role;
    private String fullName;
    private String sortCode;

    public User() {
    }

    public User(Long id, String username, String email, String passwordHash, String role,
                String fullName, String sortCode) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.role = role;
        this.fullName = fullName;
        this.sortCode = sortCode;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getSortCode() {
        return sortCode;
    }

    public void setSortCode(String sortCode) {
        this.sortCode = sortCode;
    }

    public boolean isAdmin() {
        return "admin".equalsIgnoreCase(role);
    }
}
