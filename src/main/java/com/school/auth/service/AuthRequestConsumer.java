package com.school.auth.service;

import com.school.auth.AuthService;
import com.school.auth.JwtUtil;
import com.school.auth.dto.*;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
public class AuthRequestConsumer {

    private final AuthService authService;
    private final KafkaTemplate<String, AuthResponseMessage> kafkaTemplate;
    private final JwtUtil jwtUtil;
    private static final String TOPIC = "auth-responses";

    public AuthRequestConsumer(AuthService authService, KafkaTemplate<String, AuthResponseMessage> kafkaTemplate, JwtUtil jwtUtil) {
        this.authService = authService;
        this.kafkaTemplate = kafkaTemplate;
        this.jwtUtil = jwtUtil;
    }

    @KafkaListener(topics = "auth-requests", containerFactory = "authRequestKafkaListenerFactory")
    public void consume(AuthRequestMessage request) {
        try {
            if ("LOGIN".equals(request.getAction())) {
                LoginRequest loginReq = new LoginRequest();
                loginReq.setUsername(request.getUsername());
                loginReq.setPassword(request.getPassword());
                AuthResponse res = authService.login(loginReq);
                kafkaTemplate.send(TOPIC, request.getCorrelationId(), new AuthResponseMessage(request.getCorrelationId(), res.getToken(), res.getRefreshToken(), res.getUsername(), res.getRole()));
            } else if ("REGISTER".equals(request.getAction())) {
                String token = request.getToken();
                if (token == null || !jwtUtil.validateToken(token)) {
                    kafkaTemplate.send(TOPIC, request.getCorrelationId(),
                            new AuthResponseMessage(request.getCorrelationId(), "Forbidden: Only admins can register new users"));
                    return;
                }
                String callerRole = jwtUtil.getRoleFromToken(token);
                if (!"admin".equalsIgnoreCase(callerRole) && ! "SUPER_ADMIN".equals(callerRole)) {
                    kafkaTemplate.send(TOPIC, request.getCorrelationId(),
                            new AuthResponseMessage(request.getCorrelationId(), "Forbidden: Only admins can register new users"));
                    return;
                }
                RegisterRequest registerReq = new RegisterRequest();
                registerReq.setUsername(request.getUsername());
                registerReq.setPassword(request.getPassword());
                registerReq.setRole(request.getRole());
                registerReq.setStatus(request.getStatus());
                AuthResponse res = authService.register(registerReq);
                kafkaTemplate.send(TOPIC, request.getCorrelationId(), new AuthResponseMessage(request.getCorrelationId(), res.getToken(), res.getRefreshToken(), res.getUsername(), res.getRole()));
            } else {
                kafkaTemplate.send(TOPIC, request.getCorrelationId(),
                        new AuthResponseMessage(request.getCorrelationId(), "Unknown action: " + request.getAction()));
            }
        } catch (Exception e) {
            kafkaTemplate.send(TOPIC, request.getCorrelationId(),
                    new AuthResponseMessage(request.getCorrelationId(), e.getMessage()));
        }
    }
}
