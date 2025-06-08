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

    // Render 서비스의 경우, onrender.com 도메인을 공유하기 위해 상위 도메인 설정이 필요
    @Value("${app.cookie.domain:localhost}") // application.yml 에서 설정할 도메인 주입
    private String cookieDomain;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String email = authentication.getName();
        log.info("✅ OAuth2 로그인 성공: {}", email);

        // ✅ JWT 토큰 생성
        String token = jwtTokenProvider.generateToken(authentication, List.of("USER"));
        log.info("✅ JWT 토큰 발급 완료: {}", token);

        // ✅ HttpOnly 쿠키로 토큰 설정
        Cookie cookie = new Cookie("token", URLEncoder.encode(token, StandardCharsets.UTF_8));
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60); // 1시간

        // 🔥 Render 서비스의 경우, 상위 도메인 (예: .onrender.com)을 설정하여 다른 서비스 페이지에서도 쿠키를 공유
        cookie.setDomain(cookieDomain);

        // 🔥 HTTPS 환경에서만 쿠키를 전송하도록 설정 (필수)
        cookie.setSecure(true); // Render는 HTTPS를 사용하므로 true로 설정

        // 🔥 SameSite=None 설정 추가 (CORS 환경에서 쿠키 전송을 허용)
        String cookieHeader = String.format("token=%s; Max-Age=%d; Path=/; HttpOnly; Domain=%s; Secure; SameSite=None",
                URLEncoder.encode(token, StandardCharsets.UTF_8),
                cookie.getMaxAge(),
                cookie.getDomain());
        response.addHeader("Set-Cookie", cookieHeader);
        log.info("🔁 HttpOnly, Secure, SameSite=None 쿠키 설정 완료 (도메인: {})", cookieDomain);


        // ✅ 사용자 프로필 존재 여부 확인
        var user = usersRepository.findByEmail(email).orElse(null);
        boolean hasProfile = user != null && userProfileRepository.existsById(user.getId());

        // ✅ 프로필 존재 여부에 따라 리디렉션 분기
        String redirectPath = hasProfile ? "/profile/view" : "/profile/new";
        log.info("🚀 리디렉션 경로 결정됨: {}", redirectPath);

        response.sendRedirect(redirectPath);
    }
}