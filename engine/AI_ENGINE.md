# Evidence-based AI review

The rules and SQL pipeline read, normalize and detect events without an API key. AI is a pretrained model invoked after detection; no model is trained or fine-tuned here.

1. **Select evidence.** Retrieve up to 20 incident records and 10 nearby detected records. Nearby means at most five minutes apart and a shared host, account or source/destination pair. These are candidates, not proven attack links. The character cap may reduce this packet further. Long-range, low-and-slow attacks may be missed by this contextual window.
2. **Interpret.** Groq or OpenAI receives sanitized excerpts, timestamps, packet roles, explicit limitations, a limited technique reference and a structured output schema. It proposes an assessment, technique mappings, connections and missing evidence. Generic firewall labels alone do not justify a specific technique.
3. **Validate.** Reject unknown evidence IDs, techniques outside the reference, self-links, malformed responses and unsupported response fields. Every structured mapping requires evidence IDs and a reason. These checks enforce structure and citations; they cannot prove semantic correctness. Confidence labels are model opinions, not calibrated probabilities.
4. **Preserve facts.** Store proposals separately under `ai_review` with provider, model, timestamp, prompt version and packet fingerprint. The engine graph stays unchanged. An analyst reviews proposals before accepting any interpretation. AI cannot recover missing endpoint telemetry or unreadable file sections.
5. **Limit resources.** One request at a time, configurable run-wide review count, bounded evidence text/output, timeout, disk cache and stop-on-failure. Context queries use bounded DuckDB memory but may scan disk. This is selective review, not AI processing every log line; additional findings remain unreviewed.
6. **Explain simply.** `briefs/<incident-id>.json` separates observations, engine connections, AI suggestions, missing evidence and coverage. CLI `show` prints the explanation; the application Overview shows mappings and links separately. Run the adapter after review for an updated handoff.

No-key mode retains deterministic findings and briefs. Live provider accuracy has not been measured against organizer ground truth. The reference currently covers only techniques supported by configured rules; extending it requires reviewed technique descriptions and validation examples.

## Input limitations

The supplied official file has an invalid UTF-8/binary section. Strict mode rejects it. Explicit recovery mode analyzes only complete records preceding that section and reports excluded bytes. Timestamp fields also disagree; the parser preserves the discrepancy and currently prefers epoch time. AI is informed of uncertainty, rather than asked to invent a resolution.
