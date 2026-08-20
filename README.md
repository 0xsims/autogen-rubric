# autogen-rubric

**One line. Every AI decision attested.**

Post-quantum attestation for OpenAI, Anthropic, LlamaIndex, LangChain, AutoGen, CrewAI, and more — anchored permanently to Hedera Consensus Service. Built for EU AI Act Article 12 compliance.

    pip install autogen-rubric


## Get a free API key

    https://rubric-protocol.com/get-started

Takes 10 seconds. Key is shown instantly — no waiting for email.



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
    # autogen, crewai, langgraph, dspy,
    # pydantic_ai, google.adk, openai-agents

    # NOT auto-instrumented - use the explicit integrations:
    #   Haystack:        RubricHaystackComponent / rubric_haystack_callback
    #   Semantic Kernel: get_sk_rubric_plugin / rubric_semantic_kernel_filter
    #   Strands:         instrument_strands / RubricStrandsHooks

## Configuration

    rubric.instrument(
        api_key="your-rubric-api-key",
        pipeline_id="loan-underwriting",
        node="eu",
        tier="standard",  # or "developer", "enterprise"
        enterprise=True,  # legacy alias
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

    client = RubricClient(api_key="your-key", tier="standard", background_queue=True)

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
- API keys: https://rubric-protocol.com/get-started
- Website: https://rubric-protocol.com
- Support: Scott@Rubric-Protocol.com
## Agent payment attestation — AWS Bedrock AgentCore Payments (since 1.10.0)

AgentCore Payments gives a Bedrock agent a wallet, a spend policy and an audit trail. The trail is logs: written by the same account that made the payment, after the payment, and self-asserted — the same gap that makes any agent's own record of its own spending weak evidence in a dispute.

`attest_before_spend` wraps the payment callable and writes the decision **before** the money moves. In the default `mode="enforce"`, a decision attestation that cannot be written blocks the spend: there is no path where value moves and no record exists. A log written afterwards can always be the one that never got written.

```python
from autogen_rubric import attest_before_spend

# Any payment callable: an AgentCore Payments client method, an x402 fetch
# wrapper, a treasury API. The binding point is the function, not the vendor.
pay = attest_before_spend(
    agentcore_payments.pay,          # payment_fn(params, ctx) -> result
    api_key="YOUR_RUBRIC_API_KEY",
    agent_id="procurement-agent",
    mandate_ref="mandate-8841",      # ties every spend to the authorization
    rail="x402",
    mode="enforce",                  # no attestation, no payment
)

out = pay({"to": "0xaB67...54ca", "amount": "100000"},
          intent="renew data subscription",
          payee="acme-data", amount="100000", currency="USDC")
```

Two attestations per spend: `AGENT_SPEND_DECISION` before the call and `AGENT_SPEND_RECEIPT` after it, so an authorized-but-never-settled payment is distinguishable from one that went through — a distinction the wallet balance alone cannot make.

Payment parameters are encrypted at rest under a per-attestation key Rubric returns and does not retain; `paramsHash` is the public commitment. You can prove to a counterparty exactly what the agent was instructed to pay without disclosing the instruction to anyone else, and `verify_spend_commitment(record, payload_key, expected_commitment)` checks it offline.

Any `mode` other than `"enforce"` — `"observe"`, say — records without gating while you evaluate. Everything else — wallet custody, spend limits, approval policy — stays with AgentCore; this adds the evidence layer those controls are judged against.

## Sandbox execution attestation (new in 1.8.1)

Agent sandboxes (LangSmith Sandboxes, E2B, Modal, Daytona) contain the blast radius of agent-executed code. `RubricSandbox` proves what happened inside: every command and output digest, every artifact hash, and the base snapshot — signed with ML-DSA-65 and anchored to Hedera at teardown. Sandboxes are the containment layer; this is the flight recorder.

```python
from langsmith.sandbox import SandboxClient
from autogen_rubric import RubricClient, RubricSandbox

rubric = RubricClient(api_key="YOUR_RUBRIC_API_KEY")

with SandboxClient().sandbox() as sb:
    with RubricSandbox(rubric, sb, agent_id="analysis-agent", snapshot_ref="img:py3.12-base") as rsb:
        rsb.run("python clean_dataset.py")
        rsb.run("python generate_report.py")
        rsb.register_artifact("report.pdf", open("report.pdf", "rb").read())
# On exit: one SANDBOX_RUN attestation — command digests, artifact hashes, snapshot lineage —
# independently verifiable at rubric-protocol.com/verify, years after the sandbox is gone.
```

Works with any sandbox object exposing `run()`; all other methods pass through untouched. For already-completed runs, `attest_sandbox_run(client, commands, artifacts=...)` is the one-shot form.
