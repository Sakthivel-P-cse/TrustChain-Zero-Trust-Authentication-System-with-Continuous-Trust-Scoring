INSERT INTO tenants(id, name, schema_name, active, created_at) VALUES
    ('org-a', 'Startup Org A', 'tenant_org_a', true, now()),
    ('org-b', 'Enterprise Org B', 'tenant_org_b', true, now());

INSERT INTO service_identities(service_id, tenant_id, certificate_fingerprint, allowed_actions) VALUES
    ('order-service', 'org-a', 'mock-cert-fingerprint-order', ARRAY['read:orders','write:orders']),
    ('payment-service', 'org-a', 'mock-cert-fingerprint-payment', ARRAY['read:payments','write:payments']);
