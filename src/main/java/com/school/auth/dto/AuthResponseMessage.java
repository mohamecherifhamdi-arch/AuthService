package com.school.auth.dto;

public class AuthResponseMessage {
    private String correlationId;
    private String token;
    private String refreshToken;
    private String username;
    private String role;
    private String error;

    public AuthResponseMessage() {}

    public AuthResponseMessage(String correlationId, String token, String refreshToken, String username, String role) {
        this.correlationId = correlationId;
        this.token = token;
        this.refreshToken = refreshToken;
        this.username = username;
        this.role = role;
        this.error = null;
    }

    public AuthResponseMessage(String correlationId, String error) {
        this.correlationId = correlationId;
        this.error = error;
    }

    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
}
