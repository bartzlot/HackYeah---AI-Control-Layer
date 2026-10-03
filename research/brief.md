# Brief - issuer requirements (CRIETRIA AI Control Layer PDF, sections 3 and 4, verbatim)

## 3. Expected Outcome
1. AI Control Layer: A functional gateway, proxy, middleware, or SDK wrapper (or other component) that developers can easily integrate into the AI systems (e.g. agent to agent, app to agent, agent to MCP, agent to model, etc communication).
   a) You can build your own agent OR use an already existing agent to showcase the solution.
   b) You should provide a simple diagram presenting the architecture of your solution.
2. Sample Configuration: Documented policy file configuring the controls/guardrails and demonstrating different configurable strictness/adherence levels and budget rules for those controls.
3. Simple Interactive Dashboard: UI displaying controls, overall security posture, blocked threats, and other metrics (e.g. resource consumption/cost).
4. Executable Test Suite: A ready to run test-suite which can verify implementation of your controls, including budget limits and exploit mitigation.

## 4. Formal Requirements
1. Centralized Policy Engine: A single config source (e.g. file/system) managing controls, sensitivity thresholds (Block vs Redact or adherence %), allowed LLM models, and resource/financial budgets.
2. Controls/Guardrails:
   1. Deterministic (Non-AI): e.g. pattern matching (detecting PII or secrets), checking of authentication or access requirements, etc.
   2. Semantic (AI-Based): where possible, consider using AI-based solutions/model to secure interaction with the AI systems.
3. Budget and Resource Governance: When designing the control layer, think about how to enforce budget limits (e.g. resource access, compute time or token spend for access to LLMs).
4. Historical Attack Mitigation: think about how to detect and block patterns associated with successful historical exploits on AI systems, such as malicious code execution, unsafe deserialization, or supply-chain exploits targeting model repositories.
5. Security Reporting & Auditing: real-time metrics (blocked interactions, budget usage) for management and exportable audit logs designed for security teams to analyze threats, policy violations, and system usage; can be implemented as a dedicated dashboard or otherwise.
6. Self-Testing Suite: Automated test suite verifying both positive (allowed) and negative (blocked) cases for the controls.
