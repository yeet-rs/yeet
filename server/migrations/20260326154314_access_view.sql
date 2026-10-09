CREATE VIEW IF NOT EXISTS access AS
    -- 1. Restricted Users (Specific Policies)
    SELECT
        p.user_id,
        rt.resource_id,
        rt.resource_type,
        rt.tag_id
    FROM policies p
    JOIN resource_tags rt ON p.tag_id = rt.tag_id
    JOIN users u ON u.id = p.user_id
    WHERE u.all_tag = 0

    UNION

    -- 2. Super Users (All Resources + Their Associated Tags)
    SELECT
        u.id AS user_id,
        all_resources.id,
        all_resources.resource_type,
        rt.tag_id -- Will be NULL for untagged resources, or populated with actual IDs
    FROM users u
    CROSS JOIN (
        SELECT id, 'Secret' AS resource_type FROM secrets
        UNION
        SELECT id, 'Host' AS resource_type FROM hosts
    ) all_resources
    LEFT JOIN resource_tags rt
        ON all_resources.id = rt.resource_id
        AND all_resources.resource_type = rt.resource_type
    WHERE u.all_tag = 1;
