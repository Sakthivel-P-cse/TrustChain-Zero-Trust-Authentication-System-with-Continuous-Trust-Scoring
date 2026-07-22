package dev.trustchain.domain.policy;

import dev.trustchain.domain.model.User;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class AbacEvaluator {
    private final List<Rule> rules;

    public AbacEvaluator(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    public AbacDecision evaluate(User user, Resource resource, Map<String, String> requestAttributes) {
        return evaluate(user, resource, requestAttributes, rules);
    }

    public AbacDecision evaluate(User user, Resource resource, Map<String, String> requestAttributes,
                                 List<Rule> activeRules) {
        for (Rule rule : activeRules) {
            Optional<String> denial = rule.denialReason(user, resource, requestAttributes);
            if (denial.isPresent()) {
                return new AbacDecision(false, denial.get());
            }
        }
        return new AbacDecision(true, "allowed");
    }

    @FunctionalInterface
    public interface Rule {
        Optional<String> denialReason(User user, Resource resource, Map<String, String> requestAttributes);
    }

    public record Resource(String ownerTenantId, int sensitivityLevel, Map<String, String> attributes) {
        public Resource {
            attributes = Map.copyOf(attributes);
        }
    }

    public record AbacDecision(boolean allowed, String reason) {
    }
}
