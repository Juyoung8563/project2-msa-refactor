package org.example.project2msarefactor.controller.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;

    @Value("${app.cookie.domain}")
    private String cookieDomain;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO dto, HttpServletResponse response) {
        try {
            log.info("🔐 로그인 시도: {}", dto.email());

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(dto.email(), dto.password())
            );

            String token = jwtTokenProvider.generateToken(authentication, List.of("USER"));
            log.info("✅ JWT 토큰 생성 완료: {}", token.substring(0, Math.min(20, token.length())) + "...");

            String encodedToken = URLEncoder.encode(token, StandardCharsets.UTF_8);
            int maxAge = (int) Duration.ofHours(1).getSeconds();

            if ("localhost".equals(cookieDomain)) {
                // 🏠 로컬 개발 환경
                Cookie cookie = new Cookie("token", encodedToken);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                cookie.setMaxAge(maxAge);
                response.addCookie(cookie);
                log.info("🍪 로컬 환경 쿠키 설정 완료");

            } else if ("".equals(cookieDomain)) {
                // 🚀 Render 프로덕션 환경 - 현재 도메인에서만 동작

                // 메인 쿠키 (도메인 없음)
                String cookieHeader = String.format(
                        "token=%s; Max-Age=%d; Path=/; HttpOnly; Secure; SameSite=Lax",
                        encodedToken, maxAge
                );
                response.addHeader("Set-Cookie", cookieHeader);
                log.info("🍪 Render 환경 쿠키 설정 (도메인 없음): {}", cookieHeader);

                // 백업 쿠키
                String backupCookieHeader = String.format(
                        "token_backup=%s; Max-Age=%d; Path=/; HttpOnly; Secure; SameSite=None",
                        encodedToken, maxAge
                );
                response.addHeader("Set-Cookie", backupCookieHeader);
                log.info("🍪 백업 쿠키 설정: {}", backupCookieHeader);

            } else {
                // 기타 환경
                String cookieHeader = String.format(
                        "token=%s; Max-Age=%d; Path=/; HttpOnly; Domain=%s; Secure; SameSite=None",
                        encodedToken, maxAge, cookieDomain
                );
                response.addHeader("Set-Cookie", cookieHeader);
                log.info("🍪 기타 환경 쿠키 설정 (도메인: {}): {}", cookieDomain, cookieHeader);
            }

            return ResponseEntity.ok().build();
        } catch (IllegalArgumentException e) {
            log.error("❌ 로그인 실패 (잘못된 인자): {}", e.getMessage());
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (AuthenticationException e) {
            log.error("❌ 로그인 실패 (인증 오류): {}", e.getMessage());
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
        if ("localhost".equals(cookieDomain)) {
            Cookie cookie = new Cookie("token", "");
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        } else {
            // 모든 쿠키 삭제
            String[] cookieNames = {"token", "token_backup"};
            for (String cookieName : cookieNames) {
                String deleteCookieHeader = String.format(
                        "%s=; Max-Age=0; Path=/; HttpOnly; Secure",
                        cookieName
                );
                response.addHeader("Set-Cookie", deleteCookieHeader);
            }
        }

        SecurityContextHolder.clearContext();
        return ResponseEntity.noContent().build();
    }
}