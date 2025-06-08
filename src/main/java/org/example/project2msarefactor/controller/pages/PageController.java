package org.example.project2msarefactor.controller.pages;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Slf4j
@Controller
public class PageController {

    @GetMapping("/auth/signin")
    public String signinPage() {
        return "auth/signin";
    }

    @GetMapping("/auth/signup")
    public String signupPage() {
        return "auth/signup";
    }

    @GetMapping("/profile/view")
    @PreAuthorize("isAuthenticated()")
    public String viewPage() {
        return "profile/profile-view";
    }

    @GetMapping("/profile/edit")
    @PreAuthorize("isAuthenticated()")
    public String editPage() {
        return "profile/profile-edit";
    }

    @GetMapping("/profile/new")
    public String profilePage(Authentication authentication) {
        log.info("🔍 /profile/new 페이지 요청");

        // SecurityContext에서 직접 확인
        Authentication contextAuth = SecurityContextHolder.getContext().getAuthentication();
        log.info("📋 SecurityContext 인증 정보: {}", contextAuth);
        log.info("📋 파라미터 인증 정보: {}", authentication);

        if (contextAuth != null) {
            log.info("✅ SecurityContext 인증 상태: {}, 사용자: {}",
                    contextAuth.isAuthenticated(), contextAuth.getName());
        }

        if (authentication != null) {
            log.info("✅ 파라미터 인증 상태: {}, 사용자: {}",
                    authentication.isAuthenticated(), authentication.getName());
        }

        // 두 방법 모두 확인
        if ((contextAuth == null || !contextAuth.isAuthenticated()) &&
                (authentication == null || !authentication.isAuthenticated())) {
            log.warn("❌ 인증되지 않은 사용자 - 로그인 페이지로 리디렉션");
            return "redirect:/auth/signin";
        }

        log.info("✅ 인증된 사용자 - profile/profile-new 페이지 반환");
        return "profile/profile-new";
    }
}