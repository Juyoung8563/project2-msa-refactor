package org.example.project2msarefactor.controller.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.project2msarefactor.auth.jwt.JwtTokenProvider;
import org.example.project2msarefactor.model.dto.auth.JoinDTO;
import org.example.project2msarefactor.model.dto.auth.LoginDTO;
import org.example.project2msarefactor.service.account.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;

    @Value("${app.cookie.domain:localhost}") // application.yml에서 설정할 도메인 주입
    private String cookieDomain;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO dto, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(dto.email(), dto.password())
            );

            String token = jwtTokenProvider.generateToken(authentication, List.of("USER"));

            // ✅ HttpOnly, Secure, SameSite=None 쿠키 설정 (OAuth2LoginSuccessHandler와 동일하게)
            String cookieHeader = String.format("token=%s; Max-Age=%d; Path=/; HttpOnly; Domain=%s; Secure; SameSite=None",
                    URLEncoder.encode(token, StandardCharsets.UTF_8),
                    (int) Duration.ofHours(1).getSeconds(),
                    cookieDomain);
            response.addHeader("Set-Cookie", cookieHeader);

            return ResponseEntity.ok().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body("로그인 실패. 이메일 또는 비밀번호를 확인해주세요.");
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody JoinDTO dto) {
        try {
            userService.signup(dto);
            return ResponseEntity.ok().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        // 쿠키 삭제 시에도 HttpOnly, Secure, Domain, Path를 일치시켜야 정확히 삭제됨
        String cookieHeader = String.format("token=; Max-Age=0; Path=/; HttpOnly; Domain=%s; Secure; SameSite=None",
                cookieDomain);
        response.addHeader("Set-Cookie", cookieHeader);

        // 시큐리티 컨텍스트 초기화 (optional)
        SecurityContextHolder.clearContext();

        return ResponseEntity.noContent().build();
    }
}