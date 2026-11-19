package com.securebank.core.user;

/**
 * A banking customer or staff member.
 *
 * <p>The {@code passwordHash} column holds a <b>bcrypt</b> hash with a unique salt
 * per user. See {@link PasswordService} and Lab 7 (A04).</p>
 */
public class User {

    private Long id;
    private String username;
    private String email;
    private String passwordHash;
    private String role;
    private String fullName;
    private String sortCode;
    private Boolean mustChangePassword;

    public User() {
    }

    public User(Long id, String username, String email, String passwordHash, String role,
                String fullName, String sortCode, Boolean mustChangePassword) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.role = role;
        this.fullName = fullName;
        this.sortCode = sortCode;
        this.mustChangePassword = mustChangePassword;
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
    /**
     * Whether this account still has to replace its password before it can be used.
     *
     * <p>FIXED: [A02-Lab5] a seeded administrator whose password is still the factory
     * default is flagged here and cannot be logged in with until the password is
     * changed.</p>
     */
    public boolean mustChangePassword() {
        return Boolean.TRUE.equals(mustChangePassword);
    }

    public Boolean getMustChangePassword() {
        return mustChangePassword;
    }

    public void setMustChangePassword(Boolean mustChangePassword) {
        this.mustChangePassword = mustChangePassword;
    }

    public boolean isAdmin() {
        return "admin".equalsIgnoreCase(role);
    }
}
