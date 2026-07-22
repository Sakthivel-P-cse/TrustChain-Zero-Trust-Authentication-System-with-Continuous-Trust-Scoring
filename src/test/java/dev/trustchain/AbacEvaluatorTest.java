package dev.trustchain;

import dev.trustchain.domain.model.User;
import dev.trustchain.domain.policy.AbacEvaluator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AbacEvaluatorTest {
    private final AbacEvaluator evaluator = new AbacEvaluator(List.of(
            (user, resource, attributes) -> resource.ownerTenantId().equals(user.tenantId())
                    ? Optional.empty() : Optional.of("cross_tenant_blocked"),
            (user, resource, attributes) -> user.attributes().containsKey("clearance_level")
                    && Integer.parseInt(user.attributes().get("clearance_level")) < resource.sensitivityLevel()
                    ? Optional.of("clearance_insufficient") : Optional.empty(),
            (user, resource, attributes) -> outsideHours(user, attributes)
                    ? Optional.of("outside_allowed_hours") : Optional.empty()));

    @Test
    void sameTenantPassesOwnershipRule() {
        assertThat(evaluator.evaluate(user(Map.of()), resource("org-a", 1), Map.of()).allowed()).isTrue();
    }

    @Test
    void differentTenantIsBlockedWithReason() {
        AbacEvaluator.AbacDecision decision = evaluator.evaluate(user(Map.of()), resource("org-b", 1), Map.of());
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo("cross_tenant_blocked");
    }

    @Test
    void insufficientClearanceIsBlocked() {
        AbacEvaluator.AbacDecision decision = evaluator.evaluate(user(Map.of("clearance_level", "2")),
                resource("org-a", 3), Map.of());
        assertThat(decision.reason()).isEqualTo("clearance_insufficient");
    }

    @Test
    void requestOutsideAllowedHoursIsBlocked() {
        AbacEvaluator.AbacDecision decision = evaluator.evaluate(user(Map.of("allowed_hours", "9-17")),
                resource("org-a", 1), Map.of("hour_of_day", "20"));
        assertThat(decision.reason()).isEqualTo("outside_allowed_hours");
    }

    @Test
    void requestWithNoBlockingRuleIsAllowed() {
        AbacEvaluator.AbacDecision decision = evaluator.evaluate(
                user(Map.of("clearance_level", "5", "allowed_hours", "9-17")),
                resource("org-a", 3), Map.of("hour_of_day", "12"));
        assertThat(decision.allowed()).isTrue();
    }

    private boolean outsideHours(User user, Map<String, String> attributes) {
        String allowed = user.attributes().get("allowed_hours");
        if (allowed == null) {
            return false;
        }
        String[] range = allowed.split("-");
        int hour = Integer.parseInt(attributes.get("hour_of_day"));
        return hour < Integer.parseInt(range[0]) || hour > Integer.parseInt(range[1]);
    }

    private User user(Map<String, String> attributes) {
        return new User("user-a", "org-a", "user@test", Set.of(), attributes);
    }

    private AbacEvaluator.Resource resource(String tenantId, int sensitivity) {
        return new AbacEvaluator.Resource(tenantId, sensitivity, Map.of());
    }
}
