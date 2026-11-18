package com.securebank.lab.a07;

import java.util.Map;

import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <h2>Lab 18 — Session Fixation</h2>
 * <p>OWASP A07 — Authentication Failures · Severity: Medium</p>
 *
 * <p><b>Objective:</b> pre-set a session id before login and hijack the session after
 * authentication.</p>
 *
 * <p>The session store is Tomcat's in-memory one. It is deliberately not Spring
 * Session, so that no session-id change happens behind the scenes.</p>
 */
@RestController
@RequestMapping("/api/a07")
public class Lab18SessionController {

    private final UserRepository users;

    public Lab18SessionController(UserRepository users) {
        this.users = users;
    }

    public record LoginRequest(String username, String password) {
    }

    /**
     * Issues an anonymous session so that a session id exists before authentication.
     */
    @PostMapping("/session/init")
    public ResponseEntity<?> initSession(HttpServletRequest request) {
        HttpSession session = request.getSession(true);

        return ResponseEntity.ok(Map.of(
                "session_id", session.getId(),
                "note", "Send this cookie value back with the login request."));
    }

    /**
     * Authenticates against an existing session.
     */
    @PostMapping("/auth/login-session")
    public ResponseEntity<?> loginSession(HttpServletRequest request,
                                         @RequestBody LoginRequest body) {
        String username = body.username() == null ? "" : body.username();
        String password = body.password() == null ? "" : body.password();

        // VULN: [A07-Lab18] Session Fixation - the session id that was in use BEFORE the
        // login is kept afterwards. The correct behaviour is to issue a brand new
        // session id at the moment privileges change, because an attacker who can set
        // a victim's cookie beforehand (via XSS, a shared link, or network access)
        // already knows the id that will later be authenticated.
        // FIX:  regenerate the session id on successful authentication:
        //       HttpSession old = request.getSession(false);
        //       if (old != null) {
        //           old.invalidate();
        //       }
        //       HttpSession session = request.getSession(true);
        //       session.setAttribute("userId", user.getId());
        //       Spring's request.changeSessionId() is the one-call equivalent.
        HttpSession session = request.getSession(true);

        User user = users.findByUsername(username).orElse(null);
        if (user == null || !PasswordService.matches(password, user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        session.setAttribute("userId", user.getId());
        session.setAttribute("username", user.getUsername());
        session.setAttribute("role", user.getRole());

        return ResponseEntity.ok(Map.of(
                "session_id", session.getId(),
                "session_id_changed_on_login", false,
                "user", Map.of(
                        "id", user.getId(),
                        "username", user.getUsername(),
                        "role", user.getRole())));
    }

    /**
     * Reports the identity attached to the current session.
     */
    @GetMapping("/session/whoami")
    public ResponseEntity<?> whoami(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null || session.getAttribute("username") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "No authenticated session"));
        }

        return ResponseEntity.ok(Map.of(
                "session_id", session.getId(),
                "user_id", session.getAttribute("userId"),
                "username", session.getAttribute("username"),
                "role", session.getAttribute("role")));
    }
}
