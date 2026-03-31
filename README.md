# autogen-rubric

**One line. Every AI decision attested.**

Post-quantum attestation for OpenAI, Anthropic, LlamaIndex, LangChain, AutoGen, CrewAI, and more — anchored permanently to Hedera Consensus Service. Built for EU AI Act Article 12 compliance.

    pip install autogen-rubric

## Auto-Instrumentation

Add one line at app startup. Every AI decision is attested automatically.

    import autogen_rubric as rubric

    rubric.instrument(
        api_key="your-rubric-api-key",
        pipeline_id="my-ai-app",
    )

    # Everything below is now attested automatically
    # OpenAI, Anthropic, LlamaIndex, LangChain, AutoGen, CrewAI...

Rubric detects which frameworks are installed and patches them at the framework level. Every LLM call, every agent decision, every tool use is cryptographically signed, Merkle-aggregated, and anchored to Hedera Consensus Service.

Get a free API key at rubric-protocol.com.

## What instrument() does

- Detects installed frameworks automatically
- Patches each at the class level — no per-call code required
- Submits attestations asynchronously — zero latency impact
- Stores payload keys to ./rubric_keys/ by default (configurable)
- Returns an Instrumentation object for status and shutdown

## Supported Frameworks

    # Auto-detects and instruments any of:
    # openai, anthropic, langchain, llama_index,
    # autogen, crewai, haystack, semantic_kernel,
    # langgraph, dspy

## Configuration

    rubric.instrument(
        api_key="your-rubric-api-key",
        pipeline_id="loan-underwriting",
        node="eu",
        enterprise=True,
        payload_key_dir="/secure/keys",
        on_payload_key=my_vault_store,
        background_queue=True,
        flush_interval=5.0,
    )

## Payload Key Storage

Every attestation is encrypted with a customer-held AES-256-GCM key. The key is returned once and never stored by Rubric. By default keys are written to ./rubric_keys/{attestation_id}.key

For production, provide a custom handler:

    def store_in_vault(attestation_id, payload_key):
        my_secrets_manager.store(f"rubric:{attestation_id}", payload_key)

    rubric.instrument(api_key="...", on_payload_key=store_in_vault)

Never log the payload key. Never store it next to the attestation record.

## Explicit Attestation

For custom inference layers or fine-grained control:

    from autogen_rubric import RubricClient

    client = RubricClient(api_key="your-key", enterprise=True, background_queue=True)

    result = client.attest(
        agent_id="custom-model-v2",
        output="Application approved. Confidence: 0.94.",
        confidence=0.94,
        pipeline_id="loan-underwriting",
    )

## EU AI Act Article 12

Every attested decision receives:
- ML-DSA-65 post-quantum signature (NIST FIPS 204)
- Merkle inclusion in a SHA3-256 forest
- HCS consensus timestamp from an independent network
- Poseidon2 ZK inclusion proof (customer-retrievable)
- AES-256-GCM encrypted payload (customer-held key)

The audit trail is independently verifiable without Rubric involvement.

## Links

- Documentation: https://rubric-protocol.com/docs
- API keys: https://rubric-protocol.com/developers
- Website: https://rubric-protocol.com
- Support: Scott@Rubric-Protocol.com