package org.example.project2msarefactor.model.dto.profile;

import java.util.UUID;

// 📌 조회용 (userId 포함)
public record UserProfileResponseDTO(
        UUID userId,
        String email,
        String nickname,
        String bio,
        String profileImageUrl,
        String phone
) {}