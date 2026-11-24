package com.spendwise.SpendWise.controller;

import java.util.List;
import java.util.Map;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PathVariable;

import com.spendwise.SpendWise.model.UserProfile;
import com.spendwise.SpendWise.repository.UserProfileRepository;
import com.spendwise.SpendWise.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/users")
public class UserProfileController {

    private final UserProfileRepository repo;
    private final AuthService auth;
    private final PasswordEncoder passwordEncoder;

    public UserProfileController(UserProfileRepository repo, AuthService auth, PasswordEncoder passwordEncoder) {
        this.repo = repo;
        this.auth = auth;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public ResponseEntity<?> list() {
        UserProfile current = auth.getCurrentUser();
        List<UserProfile> result = repo.findByOwnerIdOrId(current.getId(), current.getId());
        return ResponseEntity.ok(result);
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody UserProfile user) {
        UserProfile current = auth.getCurrentUser();

        // Only group accounts may add members
        if (!"group".equalsIgnoreCase(current.getAccountType())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Only group accounts can add users");
        }

        // assign ownerId to the new user so it is scoped to this group
        user.setOwnerId(current.getId());
        // ensure created users are 'individual' accounts by default
        if (user.getAccountType() == null) user.setAccountType("individual");

        // Hash password if provided and not already hashed
        if (user.getPassword() != null && !user.getPassword().isBlank()) {
            if (!user.getPassword().startsWith("$2a$") && !user.getPassword().startsWith("$2b$")) {
                user.setPassword(passwordEncoder.encode(user.getPassword()));
            }
        }

        UserProfile saved = repo.save(user);
        return ResponseEntity.ok(saved);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable Long id, @RequestBody Map<String, Object> body) {
        UserProfile current = auth.getCurrentUser();
        if (!current.getId().equals(id)) return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Not allowed");

        UserProfile user = repo.findById(id).orElse(null);
        if (user == null) return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Not found");

        if (body.get("name") != null) user.setName(body.get("name").toString());
        if (body.get("monthlyIncome") != null) user.setMonthlyIncome(Double.valueOf(body.get("monthlyIncome").toString()));
        if (body.get("profileImageUrl") != null) user.setProfileImageUrl(body.get("profileImageUrl").toString());

        if (body.get("password") != null && !body.get("password").toString().isBlank()) {
            user.setPassword(passwordEncoder.encode(body.get("password").toString()));
        }

        if (body.get("email") != null) {
            String requestedEmail = body.get("email").toString();
            UserProfile existingSameType = repo.findByEmailAndAccountType(requestedEmail, user.getAccountType());
            if (existingSameType != null && !existingSameType.getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already used for this account type");
            }
            if (!requestedEmail.equalsIgnoreCase(user.getEmail()) && repo.countByEmail(requestedEmail) >= 2) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Target email already has 2 account types");
            }
            user.setEmail(requestedEmail);
        }

        UserProfile saved = repo.save(user);
        return ResponseEntity.ok(saved);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        UserProfile current = auth.getCurrentUser();
        if (!current.getId().equals(id)) return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Not allowed");

        repo.deleteById(id);
        return ResponseEntity.ok(Map.of("status", "deleted"));
    }
}
