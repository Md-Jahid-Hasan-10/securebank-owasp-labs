package com.securebank.core.security;

/**
 * Holds the authenticated principal for the duration of the current request.
 *
 * <p>Populated by {@link AuthFilter} and cleared when the request completes.</p>
 */
public final class CurrentUserHolder {

    private static final ThreadLocal<CurrentUser> CURRENT = new ThreadLocal<>();

    private CurrentUserHolder() {
    }

    public static void set(CurrentUser user) {
        CURRENT.set(user);
    }

    /**
     * Returns the authenticated user, or {@code null} when the request is anonymous.
     */
    public static CurrentUser get() {
        return CURRENT.get();
    }

    public static void clear() {
        CURRENT.remove();
    }
}
