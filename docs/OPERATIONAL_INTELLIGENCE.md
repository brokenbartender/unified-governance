# Operational Intelligence

## AI Resource Metadata
Resources accept `ai_metadata`:
- `model_type` (llm, embedding, image-gen)
- `model_provider` (openai, anthropic, internal)
- `sensitivity_level` (1-5)
- `is_governed` (true/false)

## Usage Billing
`GET /orgs/{org_id}/usage?period=YYYY-MM` returns evaluation counts and evidence storage MB.

## Policy Generator
`POST /policies/generate` accepts `{ "text": "..." }`. If `OPENAI_API_KEY` is set, it uses the Responses API; otherwise falls back to a heuristic.

## Decision Logs
- Each evaluation is stored in `decision_logs`.
- Export summary via `GET /decision-logs/export`.

## Webhooks
- Create with `POST /webhooks`.
- Test delivery with `POST /webhooks/{id}/test`.
- Set `ENABLE_WEBHOOK_DELIVERY=true` to enable outbound delivery.
- Deliveries include `X-Webhook-Signature` header (sha256 of secret + payload).
