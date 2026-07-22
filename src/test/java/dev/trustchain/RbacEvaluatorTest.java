package dev.trustchain;

import dev.trustchain.domain.model.Permission;
import dev.trustchain.domain.model.Role;
import dev.trustchain.domain.model.User;
import dev.trustchain.domain.policy.RbacEvaluator;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RbacEvaluatorTest {
    private final RbacEvaluator evaluator = new RbacEvaluator();
    private final Permission writeOrders = new Permission("orders", "write");

    @Test
    void editorCanWriteOrders() {
        assertThat(evaluator.evaluate(user(new Role("editor", Set.of(writeOrders))), writeOrders)).isTrue();
    }

    @Test
    void viewerCannotWriteOrders() {
        Role viewer = new Role("viewer", Set.of(new Permission("orders", "read")));
        assertThat(evaluator.evaluate(user(viewer), writeOrders)).isFalse();
    }

    @Test
    void userWithoutRolesHasNoPermissions() {
        User user = new User("user", "org-a", "user@test", Set.of(), Map.of());
        assertThat(evaluator.evaluate(user, new Permission("orders", "read"))).isFalse();
        assertThat(evaluator.evaluate(user, writeOrders)).isFalse();
    }

    @Test
    void permissionsRequireExactResourceAndAction() {
        Role viewer = new Role("viewer", Set.of(new Permission("orders", "read")));
        assertThat(evaluator.evaluate(user(viewer), new Permission("payments", "read"))).isFalse();
    }

    private User user(Role role) {
        return new User("user", "org-a", "user@test", Set.of(role), Map.of());
    }
}
