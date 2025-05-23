package org.example.project2msarefactor.controller.profile;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.project2msarefactor.model.dto.profile.ProfileResponse;
import org.example.project2msarefactor.model.dto.profile.UserProfileRequestDTO;
import org.example.project2msarefactor.model.dto.profile.UserProfileResponseDTO;
import org.example.project2msarefactor.model.dto.tags.UserTagCacheDTO;
import org.example.project2msarefactor.model.repository.users.UsersRepository;
import org.example.project2msarefactor.service.profile.UserProfileService;
import org.example.project2msarefactor.service.tags.UserTagCacheService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/profile")
@RequiredArgsConstructor
public class UserProfileController {

    private final UserProfileService userProfileService;
    private final UsersRepository usersRepository;
    private final UserTagCacheService userTagCacheService;

    @GetMapping("/me/full")
    public ResponseEntity<ProfileResponse> getMyFullProfile(@AuthenticationPrincipal UserDetails userDetails) {
        String email = userDetails.getUsername();
        UUID userId = usersRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("사용자 정보를 찾을 수 없습니다."))
                .getId();

        UserProfileResponseDTO profile = userProfileService.getProfile(userId)
                .orElseThrow(() -> new RuntimeException("프로필 정보가 없습니다."));

        UserTagCacheDTO tags = userTagCacheService.getTags(userId)
                .orElse(new UserTagCacheDTO(userId, List.of(), 3, "보통"));

        return ResponseEntity.ok(new ProfileResponse(profile, tags));
    }

    @PostMapping("/me")
    public ResponseEntity<Void> saveMyProfile(@AuthenticationPrincipal UserDetails userDetails,
                                              @RequestBody @Valid UserProfileRequestDTO dto) {
        String email = userDetails.getUsername();
        UUID userId = usersRepository.findByEmail(email).orElseThrow().getId();
        userProfileService.saveProfile(userId, dto);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    public ResponseEntity<UserProfileResponseDTO> getMyProfile(@AuthenticationPrincipal UserDetails userDetails) {
        String email = userDetails.getUsername();
        return userProfileService.getProfileByEmail(email)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PatchMapping("/me")
    public ResponseEntity<Void> updateMyProfile(@AuthenticationPrincipal UserDetails userDetails,
                                                @RequestBody @Valid UserProfileRequestDTO dto) {
        String email = userDetails.getUsername();
        userProfileService.updateProfileByEmail(email, dto);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/me")
    public ResponseEntity<Void> deleteMyProfile(@AuthenticationPrincipal UserDetails userDetails) {
        String email = userDetails.getUsername();
        UUID userId = usersRepository.findByEmail(email).orElseThrow().getId();
        userProfileService.deleteProfile(userId);
        return ResponseEntity.noContent().build();
    }
}
