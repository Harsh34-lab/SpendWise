package com.spendwise.SpendWise.services;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.spendwise.SpendWise.model.UserProfile;
import com.spendwise.SpendWise.repository.UserProfileRepository;
import com.spendwise.SpendWise.security.JwtUtil;
import com.spendwise.SpendWise.security.UserPrincipal;

@Service
public class AuthService {

    private final UserProfileRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserProfileRepository repo, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.repo = repo;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public String signup(UserProfile user, String rawPassword) {
        String hashed = passwordEncoder.encode(rawPassword);
        user.setPassword(hashed);
        UserProfile saved = repo.save(user);
        return jwtUtil.generateToken(saved.getEmail(), saved.getId(), saved.getAccountType());
    }

    public String signin(String email, String rawPassword) {
        UserProfile u = repo.findByEmailAndAccountType(email, "individual");
        if (u == null) {
            u = repo.findByEmail(email);
        }
        if (u == null) return null;
        if (!verifyAndUpgradePassword(u, rawPassword)) return null;
        return jwtUtil.generateToken(u.getEmail(), u.getId(), u.getAccountType());
    }

    public String signin(String email, String rawPassword, String accountType) {
        UserProfile u = repo.findByEmailAndAccountType(email, accountType);
        if (u == null) return null;
        if (!verifyAndUpgradePassword(u, rawPassword)) return null;
        return jwtUtil.generateToken(u.getEmail(), u.getId(), u.getAccountType());
    }

    /**
     * Safely verifies raw password against stored password.
     * Supports BCrypt hashes as well as legacy plain-text passwords (auto-upgrades them to BCrypt).
     */
    private boolean verifyAndUpgradePassword(UserProfile user, String rawPassword) {
        String storedPassword = user.getPassword();
        if (storedPassword == null || rawPassword == null) {
            return false;
        }

        // Check if stored password is a BCrypt hash ($2a$, $2b$, or $2y$)
        if (storedPassword.startsWith("$2a$") || storedPassword.startsWith("$2b$") || storedPassword.startsWith("$2y$")) {
            try {
                return passwordEncoder.matches(rawPassword, storedPassword);
            } catch (Exception e) {
                return false;
            }
        }

        // Fallback for legacy plain-text passwords: if matched, upgrade to BCrypt hash in DB
        if (storedPassword.equals(rawPassword)) {
            user.setPassword(passwordEncoder.encode(rawPassword));
            repo.save(user);
            return true;
        }

        return false;
    }

    public String issueTokenForUser(UserProfile user) {
        return jwtUtil.generateToken(user.getEmail(), user.getId(), user.getAccountType());
    }

    /**
     * Retrieves the currently authenticated UserProfile from the Spring SecurityContextHolder.
     */
    public UserProfile getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserPrincipal userPrincipal) {
            return userPrincipal.getUser();
        }
        if (principal instanceof UserDetails userDetails) {
            return repo.findByEmail(userDetails.getUsername());
        }
        return null;
    }

    /**
     * Retrieves the current user's ID directly from the authenticated context.
     */
    public Long getCurrentUserId() {
        UserProfile u = getCurrentUser();
        return u != null ? u.getId() : null;
    }

    /**
     * Extracts the user from a JWT token string (supports both raw token and "Bearer " prefixed).
     * Returns null if the token is invalid or expired.
     */
    public UserProfile getByToken(String token) {
        if (token == null || token.isBlank()) return null;
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        try {
            Long userId = jwtUtil.extractUserId(token);
            if (userId == null) return null;
            if (jwtUtil.isTokenExpired(token)) return null;
            return repo.findById(userId).orElse(null);
        } catch (Exception e) {
            return null;
        }
    }
}
