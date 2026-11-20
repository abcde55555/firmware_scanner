import pytest

from experiments.version_coverage.evaluate import evaluate


def record(name, location, version="", component_type="library", vendor="Acme"):
    return {
        "name": name,
        "vendor": vendor,
        "component_type": component_type,
        "description": f"Native library at {location}",
        "resolved_version": version,
        "versions": [
            {
                "version": version,
                "method": "binary_signature",
                "evidence": f"ELF file at {location}",
            }
        ],
    }


def test_estimated_releases_count_as_usable_but_remain_distinct_from_observed_versions():
    baseline = [record(name, f"/lib/{name}.so") for name in ("observed", "estimated", "candidate")]
    observed = record("observed", "/lib/observed.so", "1.2.3")
    estimated = record("estimated", "/lib/estimated.so", "1.2.4")
    estimated["properties"] = [{"name": "firmware:version:kind", "value": "estimated-release"}]
    candidate = record("candidate", "/lib/candidate.so")
    candidate["versions"] = [{"version": "3.0.0", "method": "version_estimate"}]

    result = evaluate(baseline, [observed, estimated, candidate], {})

    metrics = result["fixed"]["all"]
    assert metrics["baseline"] == 3
    assert metrics["exact_versions"] == 1
    assert metrics["estimated_versions"] == 1
    assert metrics["usable_versions"] == 2
    assert metrics["usable_coverage"] == pytest.approx(2 / 3)
    assert metrics["usable_target_50_percent"] == "MET"
    assert metrics["independently_verified"] == 0
    assert metrics["target_50_percent"] == "NOT_MET"
    assert result["fixed"]["observations"][1]["version_kind"] == "estimated"


@pytest.mark.parametrize(
    "state",
    [
        "estimated",
        "estimated-parent-package",
        "estimated-source-revision",
    ],
)
def test_resolution_state_prevents_parent_or_source_estimates_from_counting_as_exact(state):
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    current = record("libalpha.so", "/system/lib/libalpha.so", "360499999")
    current["properties"] = [{
        "name": "firmware:version:resolution-state",
        "value": state,
    }]

    result = evaluate(baseline, [current], {})

    metrics = result["fixed"]["all"]
    assert metrics["exact_versions"] == 0
    assert metrics["estimated_versions"] == 1
    assert metrics["usable_versions"] == 1


def test_explicit_estimated_generation_is_usable_but_not_exact():
    baseline = [record("libbpf.so", "/system/lib64/libbpf.so")]
    current = record("libbpf.so", "/system/lib64/libbpf.so", "1.4.x")
    current["properties"] = [{
        "name": "firmware:version:resolution-state",
        "value": "estimated",
    }]

    result = evaluate(baseline, [current], {})

    assert result["fixed"]["all"]["exact_versions"] == 0
    assert result["fixed"]["all"]["estimated_versions"] == 1
    assert result["fixed"]["all"]["ranges"] == 0


def test_conflict_resolution_state_cannot_be_counted_as_exact():
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    current = record("libalpha.so", "/system/lib/libalpha.so", "1.2.3")
    current["properties"] = [{
        "name": "firmware:version:resolution-state",
        "value": "conflict-unresolved",
    }]

    result = evaluate(baseline, [current], {})

    assert result["fixed"]["all"]["exact_versions"] == 0
    assert result["fixed"]["all"]["unknown"] == 1


def test_explicit_taxonomy_gets_a_separate_coverage_breakdown():
    baseline = [
        record("libplatform-a.so", "/system/lib/libplatform-a.so"),
        record("libplatform-b.so", "/system/lib/libplatform-b.so"),
        record("libthirdparty.so", "/system/lib/libthirdparty.so"),
    ]
    current = [
        record("libplatform-a.so", "/system/lib/libplatform-a.so", "1.0"),
        record("libplatform-b.so", "/system/lib/libplatform-b.so"),
        record("libthirdparty.so", "/system/lib/libthirdparty.so", "2.0"),
    ]
    current[0]["properties"] = [{
        "name": "firmware:taxonomy",
        "value": "platform-first-party",
    }]
    current[1]["properties"] = [{
        "name": "firmware:taxonomy",
        "value": "platform-first-party",
    }]
    current[2]["properties"] = [{
        "name": "firmware:taxonomy",
        "value": "third-party-oss",
    }]

    result = evaluate(baseline, current, {})

    platform = result["fixed"]["by_taxonomy"]["platform-first-party"]
    third_party = result["fixed"]["by_taxonomy"]["third-party-oss"]
    assert platform["baseline"] == 2
    assert platform["usable_versions"] == 1
    assert third_party["baseline"] == 1
    assert third_party["usable_coverage"] == 1.0


def test_adjacent_estimate_agreement_is_reported_separately_from_exact_agreement():
    from experiments.version_coverage.evaluate import observation_key

    baseline = [record("libalpha.so", "/lib/libalpha.so")]
    estimated = record("libalpha.so", "/lib/libalpha.so", "1.2.4")
    estimated["versions"][0]["method"] = "version_estimate"
    expected = {observation_key(baseline[0]): "1.2.3"}

    result = evaluate(baseline, [estimated], expected)

    metrics = result["fixed"]["all"]
    assert metrics["estimated_versions"] == 1
    assert metrics["correct"] == 0
    assert metrics["errors"] == 1
    assert metrics["adjacent_estimates"] == 1
    assert metrics["accepted_verified"] == 1
    assert result["fixed"]["observations"][0]["adjacent_estimate"] is True


def test_removed_or_reclassified_baseline_records_stay_uncovered():
    baseline = [
        record("libalpha.so", "/system/lib/libalpha.so", "1.0"),
        record("libbeta.so", "/system/lib/libbeta.so", "1.0"),
    ]
    current = [
        record("libalpha.so", "/system/lib/libalpha.so", "1.0"),
        record(
            "libbeta.so",
            "/system/lib/libbeta.so",
            "1.0",
            component_type="application",
        ),
    ]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["baseline"] == 2
    assert result["fixed"]["all"]["matched"] == 1
    assert result["fixed"]["all"]["uncovered"] == 1
    assert result["fixed"]["native"]["baseline"] == 2
    assert result["fixed"]["native"]["matched"] == 1
    assert result["fixed"]["native"]["uncovered"] == 1


def test_location_set_and_normalized_identity_match_deduplicated_observation():
    baseline = [
        {
            **record("LibAlpha.SO", "/system/lib/libalpha.so"),
            "vendor": " ACME ",
            "versions": [
                {"version": "", "evidence": "ELF file at /system/lib/libalpha.so"},
                {"version": "", "evidence": "ELF file at /vendor/lib/libalpha.so"},
            ],
        }
    ]
    current = [
        {
            **record("libalpha.so", "/vendor/lib/libalpha.so"),
            "vendor": "acme",
        }
    ]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["matched"] == 1
    assert result["fixed"]["all"]["uncovered"] == 0


@pytest.mark.parametrize("property_value", [
    ["/system/app/Foo.so", "/vendor/lib/Bar.so"],
    '["/system/app/Foo.so", "/vendor/lib/Bar.so"]',
])
def test_properties_evidence_location_supports_lists_and_json(property_value):
    baseline = [{
        "name": "Foo",
        "vendor": "Acme",
        "component_type": "library",
        "properties": [{"name": "firmware:evidence:location", "value": property_value}],
    }]
    current = [{
        "name": "Foo",
        "vendor": "Acme",
        "component_type": "library",
        "properties": {"firmware:evidence:location": ["/vendor/lib/Bar.so"]},
    }]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["matched"] == 1
    assert result["fixed"]["observations"][0]["locations"] == [
        "/system/app/Foo.so",
        "/vendor/lib/Bar.so",
    ]


def test_linux_location_matching_preserves_case():
    baseline = [record("libThing.so", "/system/lib/LibThing.so")]
    current = [record("libThing.so", "/system/lib/libthing.so")]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["matched"] == 0
    assert result["fixed"]["all"]["uncovered"] == 1


def test_https_provenance_is_not_collected_as_a_file_location():
    baseline = [{
        "name": "component",
        "vendor": "Acme",
        "component_type": "library",
        "description": "Source: https://code.example.org/system/lib/component.so",
        "versions": [{"version": "1.0", "evidence": "https://code.example.org/build.prop"}],
    }]

    result = evaluate(baseline, baseline, {})

    assert result["fixed"]["observations"][0]["locations"] == []
    assert result["fixed"]["all"]["uncovered"] == 1


@pytest.mark.parametrize("explicit_version", ["", "unknown", "conflict", "detected", "detected (version unknown)"])
def test_explicit_unknown_or_conflict_resolved_version_blocks_candidate_fallback(explicit_version):
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    current = [{
        **record("libalpha.so", "/system/lib/libalpha.so", explicit_version),
        "versions": [{"version": "9.9.9", "method": "banner", "evidence": "candidate only"}],
    }]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["exact_versions"] == 0
    assert result["fixed"]["all"]["unknown"] == 1


def test_one_unknown_duplicate_does_not_discard_an_unambiguous_exact_version_in_either_order():
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    known = record("libalpha.so", "/system/lib/libalpha.so", "1.2.3")
    unknown = record("LIBALPHA.SO", "/system/lib/libalpha.so", "", vendor=" ACME ")

    for current in ([known, unknown], [unknown, known]):
        result = evaluate(baseline, current, {})
        assert result["fixed"]["all"]["exact_versions"] == 1
        assert result["fixed"]["observations"][0]["version"] == "1.2.3"


def test_conflicting_duplicate_versions_are_unknown_independent_of_input_order():
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    first = record("libalpha.so", "/system/lib/libalpha.so", "1.0")
    second = record("LIBALPHA.SO", "/system/lib/libalpha.so", "2.0", vendor=" ACME ")

    forward = evaluate(baseline, [first, second], {})
    reverse = evaluate(baseline, [second, first], {})

    assert forward["fixed"]["all"]["exact_versions"] == 0
    assert reverse["fixed"]["all"]["exact_versions"] == 0
    assert forward["fixed"]["observations"][0]["version"] == ""
    assert reverse["fixed"]["observations"][0]["version"] == ""


def test_explicit_conflict_duplicate_blocks_an_otherwise_single_exact_claim():
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    exact = record("libalpha.so", "/system/lib/libalpha.so", "1.0")
    conflict = record("LIBALPHA.SO", "/system/lib/libalpha.so", "conflict", vendor=" ACME ")

    result = evaluate(baseline, [exact, conflict], {})

    assert result["fixed"]["all"]["exact_versions"] == 0
    assert result["fixed"]["all"]["unknown"] == 1


def test_duplicate_baseline_observations_each_remain_in_the_fixed_denominator():
    baseline = [
        record("libalpha.so", "/system/lib/libalpha.so"),
        record("libalpha.so", "/system/lib/libalpha.so"),
    ]

    result = evaluate(baseline, [], {})

    assert result["fixed"]["all"]["baseline"] == 2
    assert result["fixed"]["all"]["uncovered"] == 2


def test_one_deduplicated_bom_row_covers_multiple_fixed_path_observations():
    baseline = [
        record("libalpha.so", "/system/lib64/libalpha.so"),
        record("libalpha.so", "/system/apex/example.apex!/lib64/libalpha.so"),
    ]
    current = [{
        **record("libalpha.so", "/system/lib64/libalpha.so", "1.2.3"),
        "properties": [
            {"name": "firmware:evidence:location", "value": "/system/lib64/libalpha.so"},
            {
                "name": "firmware:evidence:location",
                "value": "/system/apex/example.apex!/lib64/libalpha.so",
            },
        ],
    }]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["matched"] == 2
    assert result["fixed"]["all"]["uncovered"] == 0
    assert result["fixed"]["all"]["exact_versions"] == 2


def test_evidence_filename_without_absolute_path_is_a_source_location():
    baseline = [{
        "name": "Android",
        "vendor": "Google",
        "component_type": "operating-system",
        "versions": [{"version": "16", "evidence": "build.prop ro.build.version.release=16"}],
    }]

    result = evaluate(baseline, baseline, {})

    assert result["fixed"]["all"]["matched"] == 1
    assert result["fixed"]["observations"][0]["locations"] == ["build.prop"]


def test_records_without_locations_stay_uncovered_without_being_claimed_as_new():
    baseline = [{"name": "thing", "vendor": "Acme", "component_type": "library"}]
    result = evaluate(baseline, baseline, {})

    assert result["fixed"]["all"]["uncovered"] == 1
    assert result["new"]["records"] == 0
    assert result["new"]["unlocated_unmatched"] == 1


def test_duplicate_new_records_are_reported_once_and_do_not_change_fixed_denominator():
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    current = [
        record("libalpha.so", "/system/lib/libalpha.so"),
        record("libextra.so", "/system/lib/libextra.so", "2.0"),
        record("LIBEXTRA.SO", "/system/lib/libextra.so", "2.0", vendor=" ACME "),
    ]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["baseline"] == 1
    assert result["fixed"]["all"]["matched"] == 1
    assert result["new"]["records"] == 1


def test_conflicting_duplicate_outputs_do_not_choose_an_arbitrary_exact_version():
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    current = [
        record("libalpha.so", "/system/lib/libalpha.so", "1.0"),
        record("LIBALPHA.SO", "/system/lib/libalpha.so", "2.0", vendor=" ACME "),
    ]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["matched"] == 1
    assert result["fixed"]["all"]["exact_versions"] == 0
    assert result["fixed"]["all"]["unknown"] == 1


def test_only_independently_verified_exact_values_are_correct_and_wrong_values_are_errors():
    baseline = [record("libalpha.so", "/system/lib/libalpha.so")]
    current = [record("libalpha.so", "/system/lib/libalpha.so", "2.0")]
    key = evaluate(baseline, current, {})["fixed"]["observations"][0]["observation_key"]

    result = evaluate(baseline, current, {key: "1.0"})

    assert result["fixed"]["all"]["independently_verified"] == 1
    assert result["fixed"]["all"]["correct"] == 0
    assert result["fixed"]["all"]["errors"] == 1
    assert result["fixed"]["all"]["correct_coverage"] == 0.0


def test_unknown_and_range_values_are_not_exact_or_counted_as_correct():
    baseline = [
        record("libunknown.so", "/system/lib/libunknown.so", "unknown"),
        record("librange.so", "/system/lib/librange.so", ">=1.0,<2.0"),
        record("libwildcard.so", "/system/lib/libwildcard.so", "1.2.x"),
    ]
    current = [
        record("libunknown.so", "/system/lib/libunknown.so", "unknown"),
        record("librange.so", "/system/lib/librange.so", ">=1.0,<2.0"),
        record("libwildcard.so", "/system/lib/libwildcard.so", "1.2.x"),
    ]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["exact_versions"] == 0
    assert result["fixed"]["all"]["correct"] == 0
    assert result["fixed"]["all"]["unknown"] == 1
    assert result["fixed"]["all"]["ranges"] == 2


def test_native_definition_and_target_are_separate_from_nonempty_version_fields():
    baseline = [
        record("libnative.so", "/system/lib/libnative.so", ""),
        record("tool", "/system/bin/tool", "9", component_type="application"),
    ]
    current = [
        record("libnative.so", "/system/lib/libnative.so", "9"),
        record("tool", "/system/bin/tool", "9", component_type="application"),
    ]

    result = evaluate(baseline, current, {})

    assert result["fixed"]["all"]["exact_versions"] == 2
    assert result["fixed"]["all"]["correct"] == 0
    assert result["fixed"]["all"]["target_50_percent"] == "NOT_MET"
    assert result["fixed"]["native"]["baseline"] == 1
    assert result["new"]["records"] == 0
