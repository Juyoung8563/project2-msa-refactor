package org.example.project2msarefactor.service.account;

import lombok.RequiredArgsConstructor;
import org.example.project2msarefactor.model.dto.auth.JoinDTO;
import org.example.project2msarefactor.model.dto.auth.LoginDTO;
import org.example.project2msarefactor.model.entity.users.Users;
import org.example.project2msarefactor.model.repository.users.UsersRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    public UUID signup(JoinDTO dto) {
        if (usersRepository.existsByEmail(dto.email())) {
            throw new IllegalArgumentException("이미 가입된 이메일입니다.");
        }

        Users user = new Users();
        user.setEmail(dto.email());
        user.setPassword(passwordEncoder.encode(dto.password()));
        user.setRole("USER");
        user.setProvider("local");

        usersRepository.save(user);
        return user.getId();
    }

    public Users login(LoginDTO dto) {
        Users user = usersRepository.findByEmail(dto.email())
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 이메일입니다."));

        if (!"local".equalsIgnoreCase(user.getProvider())) {
            throw new IllegalArgumentException("소셜 로그인 계정입니다. 일반 로그인을 사용할 수 없습니다.");
        }

        if (!passwordEncoder.matches(dto.password(), user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        return user;
    }

}