package com.school.auth;

import com.school.auth.dto.AuthResponse;
import com.school.auth.dto.LoginRequest;
import com.school.auth.dto.RegisterRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService - Tests unitaires")
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    private static final String USERNAME = "jdupont";
    private static final String RAW_PASSWORD = "P@ssw0rd123";
    private static final String ENCODED_PASSWORD = "$2a$10$encodedPasswordHash";
    private static final String ROLE = "STUDENT";
    private static final String ACCESS_TOKEN = "access-token-abc";
    private static final String REFRESH_TOKEN = "refresh-token-xyz";

    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private User existingUser;

    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest();
        registerRequest.setUsername(USERNAME);
        registerRequest.setPassword(RAW_PASSWORD);
        registerRequest.setRole(ROLE);
        registerRequest.setStatus(null);

        loginRequest = new LoginRequest();
        loginRequest.setUsername(USERNAME);
        loginRequest.setPassword(RAW_PASSWORD);

        existingUser = new User(USERNAME, ENCODED_PASSWORD, ROLE, "ACTIF");
    }

    // ------------------------------------------------------------------
    // register()
    // ------------------------------------------------------------------
    @Nested
    @DisplayName("register()")
    class Register {

        @Test
        @DisplayName("Doit créer un utilisateur et retourner les tokens quand le username est disponible")
        void shouldRegisterUser_whenUsernameDoesNotExist() {
            when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
            when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(jwtUtil.generateToken(any(User.class))).thenReturn(ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(any(User.class))).thenReturn(REFRESH_TOKEN);

            AuthResponse response = authService.register(registerRequest);

            assertThat(response.getToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
            assertThat(response.getUsername()).isEqualTo(USERNAME);
            assertThat(response.getRole()).isEqualTo(ROLE);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getUsername()).isEqualTo(USERNAME);
            assertThat(savedUser.getPassword()).isEqualTo(ENCODED_PASSWORD);
            assertThat(savedUser.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
            assertThat(savedUser.getEmail()).isEqualTo(USERNAME);
            assertThat(savedUser.getCreatedAt()).isNotNull();
        }

        @Test
        @DisplayName("Doit utiliser le statut ACTIVE par défaut quand aucun statut n'est fourni")
        void shouldDefaultStatusToActive_whenStatusIsNull() {
            registerRequest.setStatus(null);
            when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
            when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(jwtUtil.generateToken(any(User.class))).thenReturn(ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(any(User.class))).thenReturn(REFRESH_TOKEN);

            authService.register(registerRequest);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getStatus()).isEqualTo("ACTIF");
        }

        @Test
        @DisplayName("Doit conserver le statut fourni quand il est explicitement renseigné")
        void shouldKeepProvidedStatus_whenStatusIsNotNull() {
            registerRequest.setStatus("PENDING");
            when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
            when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(ENCODED_PASSWORD);
            when(jwtUtil.generateToken(any(User.class))).thenReturn(ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(any(User.class))).thenReturn(REFRESH_TOKEN);

            authService.register(registerRequest);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getStatus()).isEqualTo("PENDING");
        }

        @Test
        @DisplayName("Doit lever une exception quand le username existe déjà")
        void shouldThrowException_whenUsernameAlreadyExists() {
            when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

            assertThatThrownBy(() -> authService.register(registerRequest))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Username already exists");

            verify(userRepository, never()).save(any(User.class));
            verifyNoInteractions(jwtUtil);
        }
    }

    // ------------------------------------------------------------------
    // login()
    // ------------------------------------------------------------------
    @Nested
    @DisplayName("login()")
    class Login {

        @Test
        @DisplayName("Doit retourner les tokens quand les identifiants sont valides et le compte actif")
        void shouldReturnTokens_whenCredentialsValidAndAccountActive() {
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existingUser));
            when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
            when(jwtUtil.generateToken(any(User.class))).thenReturn(ACCESS_TOKEN);
            when(jwtUtil.generateRefreshToken(any(User.class))).thenReturn(REFRESH_TOKEN);

            AuthResponse response = authService.login(loginRequest);

            assertThat(response.getToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
            assertThat(response.getUsername()).isEqualTo(USERNAME);
            assertThat(response.getRole()).isEqualTo(ROLE);
            verify(userRepository).save(existingUser);
            assertThat(existingUser.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Doit lever une exception quand l'utilisateur n'existe pas")
        void shouldThrowException_whenUserNotFound() {
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.login(loginRequest))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Invalid username or password");

            verify(userRepository, never()).save(any(User.class));
        }

        @Test
        @DisplayName("Doit lever une exception quand le mot de passe est incorrect")
        void shouldThrowException_whenPasswordDoesNotMatch() {
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existingUser));
            when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(false);

            assertThatThrownBy(() -> authService.login(loginRequest))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Invalid username or password");

            verify(userRepository, never()).save(any(User.class));
            verifyNoInteractions(jwtUtil);
        }

        @Test
        @DisplayName("Doit lever une exception quand le compte n'est pas actif")
        void shouldThrowException_whenAccountNotActive() {
            User inactiveUser = new User(USERNAME, ENCODED_PASSWORD, ROLE, "SUSPENDED");
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(inactiveUser));
            when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);

            assertThatThrownBy(() -> authService.login(loginRequest))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Account is not active");

            verify(userRepository, never()).save(any(User.class));
            verifyNoInteractions(jwtUtil);
        }
    }

    // ------------------------------------------------------------------
    // validateToken()
    // ------------------------------------------------------------------
    @Nested
    @DisplayName("validateToken()")
    class ValidateToken {

        @Test
        @DisplayName("Doit retourner username/role quand le token est valide et n'est pas un refresh token")
        void shouldReturnAuthResponse_whenTokenIsValid() {
            when(jwtUtil.validateToken(ACCESS_TOKEN)).thenReturn(true);
            when(jwtUtil.isRefreshToken(ACCESS_TOKEN)).thenReturn(false);
            when(jwtUtil.getUsernameFromToken(ACCESS_TOKEN)).thenReturn(USERNAME);
            when(jwtUtil.getRoleFromToken(ACCESS_TOKEN)).thenReturn(ROLE);
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existingUser));  // ← ajouter cette ligne
            AuthResponse response = authService.validateToken(ACCESS_TOKEN);

            assertThat(response.getToken()).isNull();
            assertThat(response.getRefreshToken()).isNull();
            assertThat(response.getUsername()).isEqualTo(USERNAME);
            assertThat(response.getRole()).isEqualTo(ROLE);
        }

        @Test
        @DisplayName("Doit lever une exception quand le token est invalide")
        void shouldThrowException_whenTokenIsInvalid() {
            when(jwtUtil.validateToken(ACCESS_TOKEN)).thenReturn(false);

            assertThatThrownBy(() -> authService.validateToken(ACCESS_TOKEN))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Invalid or expired token");
        }

        @Test
        @DisplayName("Doit lever une exception quand le token est un refresh token")
        void shouldThrowException_whenTokenIsRefreshToken() {
            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.isRefreshToken(REFRESH_TOKEN)).thenReturn(true);

            assertThatThrownBy(() -> authService.validateToken(REFRESH_TOKEN))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Invalid or expired token");
        }
    }

    // ------------------------------------------------------------------
    // refreshAccessToken()
    // ------------------------------------------------------------------
    @Nested
    @DisplayName("refreshAccessToken()")
    class RefreshAccessToken {

        @Test
        @DisplayName("Doit retourner de nouveaux tokens quand le refresh token est valide, actif et non révoqué")
        void shouldReturnNewTokens_whenRefreshTokenValid() {
            existingUser.setRefreshToken(REFRESH_TOKEN);
            String newAccessToken = "new-access-token";
            String newRefreshToken = "new-refresh-token";

            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.isRefreshToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.getUsernameFromToken(REFRESH_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existingUser));
            when(jwtUtil.generateToken(any(User.class))).thenReturn(newAccessToken);
            when(jwtUtil.generateRefreshToken(any(User.class))).thenReturn(newRefreshToken);

            AuthResponse response = authService.refreshAccessToken(REFRESH_TOKEN);

            assertThat(response.getToken()).isEqualTo(newAccessToken);
            assertThat(response.getRefreshToken()).isEqualTo(newRefreshToken);
            assertThat(existingUser.getRefreshToken()).isEqualTo(newRefreshToken);
            verify(userRepository).save(existingUser);
        }

        @Test
        @DisplayName("Doit lever une exception quand le token est invalide")
        void shouldThrowException_whenTokenIsInvalid() {
            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(false);

            assertThatThrownBy(() -> authService.refreshAccessToken(REFRESH_TOKEN))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Invalid refresh token");

            verifyNoInteractions(userRepository);
        }

        @Test
        @DisplayName("Doit lever une exception quand le token n'est pas un refresh token")
        void shouldThrowException_whenTokenIsNotRefreshToken() {
            when(jwtUtil.validateToken(ACCESS_TOKEN)).thenReturn(true);
            when(jwtUtil.isRefreshToken(ACCESS_TOKEN)).thenReturn(false);

            assertThatThrownBy(() -> authService.refreshAccessToken(ACCESS_TOKEN))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Invalid refresh token");

            verifyNoInteractions(userRepository);
        }

        @Test
        @DisplayName("Doit lever une exception quand l'utilisateur n'est pas trouvé")
        void shouldThrowException_whenUserNotFound() {
            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.isRefreshToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.getUsernameFromToken(REFRESH_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.refreshAccessToken(REFRESH_TOKEN))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("User not found");

            verify(userRepository, never()).save(any(User.class));
        }

        @Test
        @DisplayName("Doit lever une exception quand le compte n'est pas actif")
        void shouldThrowException_whenAccountNotActive() {
            User inactiveUser = new User(USERNAME, ENCODED_PASSWORD, ROLE, "SUSPENDED");
            inactiveUser.setRefreshToken(REFRESH_TOKEN);

            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.isRefreshToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.getUsernameFromToken(REFRESH_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(inactiveUser));

            assertThatThrownBy(() -> authService.refreshAccessToken(REFRESH_TOKEN))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Account is not active");

            verify(userRepository, never()).save(any(User.class));
        }

        @Test
        @DisplayName("Doit lever une exception quand le refresh token a été révoqué (ne correspond pas à celui stocké)")
        void shouldThrowException_whenRefreshTokenIsRevoked() {
            existingUser.setRefreshToken("un-autre-token-stocke");

            when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.isRefreshToken(REFRESH_TOKEN)).thenReturn(true);
            when(jwtUtil.getUsernameFromToken(REFRESH_TOKEN)).thenReturn(USERNAME);
            when(userRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existingUser));

            assertThatThrownBy(() -> authService.refreshAccessToken(REFRESH_TOKEN))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Refresh token has been revoked");

            verify(userRepository, never()).save(any(User.class));
        }
    }
}