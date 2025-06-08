package org.example.project2msarefactor.auth.oauth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.project2msarefactor.auth.jwt.JwtTokenProvider;
import org.example.project2msarefactor.model.repository.profile.UserProfileRepository;
import org.example.project2msarefactor.model.repository.users.UsersRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements org.springframework.security.web.authentication.AuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final UsersRepository usersRepository;
    private final UserProfileRepository userProfileRepository;

    @Value("${front-end.redirect:/profile/view}")
    private String frontRedirectUrl;

    @Value("${app.cookie.domain:localhost}")
    private String cookieDomain;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String email = authentication.getName();
        log.info("✅ OAuth2 로그인 성공: {}", email);

        String token = jwtTokenProvider.generateToken(authentication, List.of("USER"));
        log.info("✅ JWT 토큰 발급 완료: {}", token.substring(0, Math.min(20, token.length())) + "...");

        // 현재 호스트 정보 로깅
        String host = request.getHeader("Host");
        String scheme = request.getScheme();
        boolean isHttps = "https".equals(scheme);
        log.info("🌐 현재 요청 정보 - Host: {}, Scheme: {}, HTTPS: {}", host, scheme, isHttps);

        String encodedToken = URLEncoder.encode(token, StandardCharsets.UTF_8);

        if ("localhost".equals(cookieDomain)) {
            // 🏠 로컬 개발 환경
            Cookie cookie = new Cookie("token", encodedToken);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(60 * 60);
            response.addCookie(cookie);
            log.info("🍪 로컬 환경 쿠키 설정 완료");

        } else if ("".equals(cookieDomain)) {
            // 🚀 Render 프로덕션 환경 - 현재 도메인에서만 동작

            // 방법 1: Set-Cookie 헤더로 도메인 없이 설정
            String cookieHeader = String.format(
                    "token=%s; Max-Age=%d; Path=/; HttpOnly; Secure; SameSite=Lax",
                    encodedToken, 60 * 60
            );
            response.addHeader("Set-Cookie", cookieHeader);
            log.info("🍪 Render 환경 쿠키 설정 (도메인 없음): {}", cookieHeader);

            // 방법 2: 백업용 쿠키 (SameSite=None으로 다른 정책 시도)
            String backupCookieHeader = String.format(
                    "token_backup=%s; Max-Age=%d; Path=/; HttpOnly; Secure; SameSite=None",
                    encodedToken, 60 * 60
            );
            response.addHeader("Set-Cookie", backupCookieHeader);
            log.info("🍪 백업 쿠키 설정: {}", backupCookieHeader);

        } else {
            // 기타 환경 (원래 도메인 설정 사용)
            String cookieHeader = String.format(
                    "token=%s; Max-Age=%d; Path=/; HttpOnly; Domain=%s; Secure; SameSite=None",
                    encodedToken, 60 * 60, cookieDomain
            );
            response.addHeader("Set-Cookie", cookieHeader);
            log.info("🍪 기타 환경 쿠키 설정 (도메인: {}): {}", cookieDomain, cookieHeader);
        }

        // 사용자 프로필 존재 여부 확인
        var user = usersRepository.findByEmail(email).orElse(null);
        boolean hasProfile = user != null && userProfileRepository.existsById(user.getId());

        String redirectPath = hasProfile ? "/profile/view" : "/profile/new";
        log.info("🚀 OAuth2 리디렉션 경로 결정됨: {}", redirectPath);

        response.sendRedirect(redirectPath);
    }
}