package dev.trustchain.domain.model;

import java.util.Map;
import java.util.Set;

public record User(String id, String tenantId, String email, Set<Role> roles, Map<String, String> attributes) {
    public User {
        roles = Set.copyOf(roles);
        attributes = Map.copyOf(attributes);
    }
}
