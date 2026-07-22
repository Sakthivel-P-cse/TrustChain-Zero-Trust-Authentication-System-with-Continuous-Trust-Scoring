package dev.trustchain.domain.port;

import dev.trustchain.domain.model.User;

import java.util.Optional;

public interface UserRepository {
    Optional<User> findById(String id);

    Optional<User> findByEmail(String email);

    Optional<String> findPasswordHash(String userId);

    void save(User user, String passwordHash);
}
