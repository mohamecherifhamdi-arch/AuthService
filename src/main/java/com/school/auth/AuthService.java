package com.school.auth;

import com.school.auth.dto.AuthResponse;
import com.school.auth.dto.LoginRequest;
import com.school.auth.dto.RegisterRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }
        String status = request.getStatus() != null ? request.getStatus() : "ACTIVE";
        User user = new User(request.getUsername(), passwordEncoder.encode(request.getPassword()), request.getRole(), status);
        String token = jwtUtil.generateToken(user.getUsername(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());
        user.setRefreshToken(refreshToken);
        user.setEmail(request.getUsername() + "@ecole.fr");
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);
        return new AuthResponse(token, refreshToken, user.getUsername(), user.getRole());
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid username or password");
        }
        if (!"ACTIVE".equals(user.getStatus())) {
            throw new RuntimeException("Account is not active");
        }
        String token = jwtUtil.generateToken(user.getUsername(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
        return new AuthResponse(token, refreshToken, user.getUsername(), user.getRole());
    }

    public AuthResponse validateToken(String token) {
        if (!jwtUtil.validateToken(token) || jwtUtil.isRefreshToken(token)) {
            throw new RuntimeException("Invalid or expired token");
        }
        String username = jwtUtil.getUsernameFromToken(token);
        String role = jwtUtil.getRoleFromToken(token);
        return new AuthResponse(null, null, username, role);
    }

    public AuthResponse refreshAccessToken(String refreshTokenValue) {
        if (!jwtUtil.validateToken(refreshTokenValue) || !jwtUtil.isRefreshToken(refreshTokenValue)) {
            throw new RuntimeException("Invalid refresh token");
        }
        String username = jwtUtil.getUsernameFromToken(refreshTokenValue);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (!"ACTIVE".equals(user.getStatus())) {
            throw new RuntimeException("Account is not active");
        }
        if (!refreshTokenValue.equals(user.getRefreshToken())) {
            throw new RuntimeException("Refresh token has been revoked");
        }
        String newToken = jwtUtil.generateToken(user.getUsername(), user.getRole());
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getUsername());
        user.setRefreshToken(newRefreshToken);
        userRepository.save(user);
        return new AuthResponse(newToken, newRefreshToken, user.getUsername(), user.getRole());
    }
}
