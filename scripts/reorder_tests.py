#!/usr/bin/env python3
"""Reorder whole `#[test] fn` blocks within a test module by a given order.

Only permutes complete test functions; never edits a test body. Verifies the
set of moved functions matches the expected order and that the region's
non-blank lines are an exact permutation of the original.
"""
import re
import sys


def reorder(path, jobs):
    with open(path) as f:
        lines = f.readlines()

    # Process jobs from the bottom of the file up so earlier line anchors stay valid.
    for start_line, fn_indent, order in sorted(jobs, key=lambda j: -j[0]):
        i = start_line - 1  # 0-indexed `mod ... {` line
        test_marker = fn_indent + "#[test]"
        close_line = fn_indent + "}\n"

        # find first test
        while not lines[i].startswith(test_marker):
            i += 1
        region_start = i

        units = {}  # name -> list of lines (ends at fn close line)
        k = i
        order_seen = []
        while lines[k].startswith(test_marker):
            unit = [lines[k]]
            k += 1
            name = None
            while True:
                unit.append(lines[k])
                m = re.match(r"\s*fn ([a-zA-Z0-9_]+)", lines[k])
                if name is None and m:
                    name = m.group(1)
                if lines[k] == close_line:
                    k += 1
                    break
                k += 1
            assert name is not None, f"no fn name in unit near line {region_start}"
            units[name] = unit
            order_seen.append(name)
            # skip blank separators
            while k < len(lines) and lines[k].strip() == "":
                k += 1
            if not (k < len(lines) and lines[k].startswith(test_marker)):
                break
        region_end = k

        assert set(order) == set(units), (
            f"{path}: order mismatch\n in_order_not_file={set(order)-set(units)}\n"
            f" in_file_not_order={set(units)-set(order)}"
        )

        original = lines[region_start:region_end]
        rebuilt = []
        for name in order:
            rebuilt.extend(units[name])
            rebuilt.append("\n")

        # exact permutation check on non-blank lines
        assert sorted(l for l in original if l.strip()) == sorted(
            l for l in rebuilt if l.strip()
        ), f"{path}: non-blank lines changed during reorder"

        lines[region_start:region_end] = rebuilt
        print(f"{path}: reordered {len(order)} tests at line {start_line}")

    with open(path, "w") as f:
        f.writelines(lines)


PROJECT_FACT = "src/core/project_fact.rs"
MESSAGE = "src/protocol/content/message/project.rs"

CONTRACT_ORDER = [
    "projection_drain_revisits_dependent_after_offer_commits",
    "projection_drain_resolves_new_need_that_matches_existing_offer",
    "projection_drain_attaches_all_satisfied_context_when_later_need_wakes",
    "projection_drain_uses_context_attached_to_pending_queue",
    "incoming_fact_missing_context_is_retained_and_parked",
    "ephemeral_input_can_use_existing_durable_context",
    "ephemeral_input_queues_child_fact_for_projection",
    "projection_drain_isolates_a_failed_fact_without_rolling_back_previous_items",
    "projection_drain_keeps_a_context_inconsistent_fact_as_evidence",
    "child_fact_projection_error_isolated_after_parent_commits",
    "projection_storage_mismatch_consumes_pending_without_committing_projector_effects",
    "projection_run_replaces_need_with_intent_when_context_appears",
    "projection_drain_resolves_exact_need_that_matches_existing_range_offer",
    "projection_drain_resolves_range_need_that_matches_existing_exact_offer",
    "projection_commit_wakes_readded_need_against_current_context",
    "projection_drain_can_keep_reemitted_need_after_it_matches",
    "projection_commit_keeps_existing_offer_when_owner_reprojects_without_it",
    "child_fact_parking_counts_as_successful_parent_projection",
    "ephemeral_input_cannot_emit_effects_while_transient_needs_remain",
    "ephemeral_input_cannot_emit_durable_offers",
    "projection_evaluation_does_not_clear_rejected_durable_pending_work",
    "projection_evaluation_does_not_delete_rejected_incoming_input",
    "projection_rejects_unregistered_intent_output",
    "projection_prepare_records_only_projector_output_context",
    "projection_run_allows_self_purge",
    "projection_run_rejects_purge_owned_by_another_fact",
    "projection_run_rejects_offer_owned_by_another_fact",
    "projection_run_rejects_need_owned_by_another_fact",
    "projection_run_rejects_time_wake_owned_by_another_fact",
    "incoming_fact_origin_metadata_is_volatile_after_fact_is_retained",
    "emitted_incoming_fact_can_preserve_origin_metadata",
    "projection_commit_records_projected_at_with_origin_receive_time",
    "projection_timing_preserves_first_projected_at_across_reprojection",
    "exact_context_lookup_plan_uses_exact_key_index",
]

TESTS_ORDER = [
    "duplicate_fact_bytes_are_idempotent_even_with_different_local_admissions",
    "purge_fact_clears_owner_keyed_and_offer_keyed_runtime_rows",
    "delete_incoming_fact_clears_owner_keyed_runtime_rows",
    "priority_pending_projection_runs_before_older_normal_work",
    "next_incoming_projection_item_reads_oldest_incoming_fact_without_context_filter",
    "projection_context_returns_matched_payloads_by_need",
    "projection_output_exposes_normalized_replacement_context",
    "projection_output_keeps_context_and_work_separate",
    "fact_route_records_projector_metadata",
]

EFFECTS_ORDER = [
    "purge_need_and_offer_match_same_opaque_key",
    "purge_range_need_spans_matching_offer_key",
    "purge_range_offer_spans_matching_need_key",
]

PROJECTOR_ORDER = [
    "content_message_projector_materializes_after_signer_author_and_secret_context",
    "content_message_projector_waits_without_materializing_before_context",
    "content_message_projector_waits_without_materializing_before_secret_context",
    "content_message_keeps_deletion_watch_and_deletes_when_matched",
    "content_message_rejects_delete_offer_from_non_author_claim",
    "expired_content_message_retracts_before_context_wait",
    "content_message_row_builders_use_registry_typed_schemas",
    "content_purge_coordinate_supports_exact_and_range_offers",
    "content_message_projector_rejects_malformed_fact_bytes",
]

AUTH_ORDER = [
    "authenticates_canonical_fact",
    "rejects_id_not_matching_bytes",
    "rejects_wrong_tag",
    "rejects_truncated_bytes",
]

DECODE_ORDER = [
    "content_message_roundtrips_fixed_width",
    "rejects_wrong_tag",
    "rejects_wrong_length",
]

reorder(
    PROJECT_FACT,
    [
        (2828, "        ", EFFECTS_ORDER),
        (3661, "    ", CONTRACT_ORDER),
        (5469, "    ", TESTS_ORDER),
    ],
)

reorder(
    MESSAGE,
    [
        (65, "        ", DECODE_ORDER),
        (149, "        ", AUTH_ORDER),
        (1025, "    ", PROJECTOR_ORDER),
    ],
)
