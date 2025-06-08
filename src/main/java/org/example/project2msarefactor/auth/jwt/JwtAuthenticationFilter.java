package org.example.project2msarefactor.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        String uri = req.getRequestURI();
        log.info("🔍 JwtAuthenticationFilter 진입 - 요청 URI: {}", uri);

        String token = null;

        // 1️⃣ Authorization 헤더 우선
        String authHeader = req.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            log.info("✅ Authorization 헤더에서 토큰 추출: {}", token.substring(0, Math.min(20, token.length())) + "...");
        }

        // 2️⃣ 없으면 쿠키에서 검색 (다중 쿠키 지원)
        if (token == null && req.getCookies() != null) {
            log.info("📋 쿠키 목록 확인:");

            // 우선순위 순서로 쿠키 검색
            String[] cookieNames = {"token", "token_backup", "token_fallback"};

            for (Cookie cookie : req.getCookies()) {
                log.info("  - 쿠키명: {}, 값 길이: {}", cookie.getName(), cookie.getValue().length());
            }

            for (String cookieName : cookieNames) {
                for (Cookie cookie : req.getCookies()) {
                    if (cookieName.equals(cookie.getName())) {
                        token = URLDecoder.decode(cookie.getValue(), StandardCharsets.UTF_8);
                        log.info("✅ {}에서 토큰 추출 성공: {}", cookieName, token.substring(0, Math.min(20, token.length())) + "...");
                        break;
                    }
                }
                if (token != null) break; // 토큰을 찾으면 중단
            }

            if (token == null) {
                log.warn("❌ 모든 쿠키에서 토큰을 찾을 수 없음");
            }
        }

        // 3️⃣ 유효성 검증 및 인증 컨텍스트 설정
        if (token != null) {
            try {
                boolean valid = jwtTokenProvider.validateToken(token);
                log.info("🔐 JWT 유효성 검사 결과: {}", valid);

                if (valid) {
                    Authentication auth = jwtTokenProvider.getAuthentication(token);
                    log.info("✅ 인증 객체 생성 성공: {}", auth.getName());
                    SecurityContextHolder.getContext().setAuthentication(auth);
                } else {
                    log.warn("❌ 유효하지 않은 JWT 토큰");
                }
            } catch (Exception e) {
                log.error("❌ JWT 토큰 처리 중 오류 발생: {}", e.getMessage());
            }
        } else {
            log.warn("❌ JWT 토큰이 없음 - 인증되지 않은 요청");
        }

        // 현재 인증 상태 로깅
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        if (currentAuth != null && currentAuth.isAuthenticated()) {
            log.info("✅ 현재 인증된 사용자: {}", currentAuth.getName());
        } else {
            log.warn("❌ 현재 인증되지 않은 상태");
        }

        chain.doFilter(req, res);
    }
}