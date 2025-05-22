package org.example.project2msarefactor.model.dto.profile;


import org.example.project2msarefactor.model.dto.tags.UserTagCacheDTO;

public record ProfileResponse(
        UserProfileResponseDTO profile,
        UserTagCacheDTO tags
) {}