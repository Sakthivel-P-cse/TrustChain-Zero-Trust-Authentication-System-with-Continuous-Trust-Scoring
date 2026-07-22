package dev.trustchain.domain.policy;

import dev.trustchain.domain.model.Permission;
import dev.trustchain.domain.model.User;

public final class RbacEvaluator {
    public boolean evaluate(User user, Permission requiredPermission) {
        return user.roles().stream()
                .flatMap(role -> role.permissions().stream())
                .anyMatch(requiredPermission::equals);
    }
}
