"""The deterministic rule set.

Each rule is a named regular expression with a category and a severity. Rules
return labelled matches, never a bare boolean, so every finding can say exactly
which words triggered it.

Categories follow the publicly documented prompt-injection families (OWASP LLM01;
Greshake et al., arXiv:2302.12173; Perez & Ribeiro, arXiv:2211.09527):

  override      — "ignore the previous instructions", "new instructions:"
  role          — fake system/assistant turns, chat-template tokens, "developer mode"
  exfiltration  — "reveal your system prompt", markdown-image beacons, "send … to"
  tool_hijack   — fake tool-call syntax, "call the X tool"
  delimiter     — "end of document", "begin system instructions"
  addressed     — text written *to* a model: "if you are an AI…"
  secrecy       — "do not tell the user"

Patterns are deliberately specific. "Please ignore the previous email" is not an
injection, and the corpus in corpus/benign/ exists to keep it that way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from archibald.models import Severity

FLAGS = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]


def _r(id: str, category: str, severity: Severity, message: str, pattern: str) -> Rule:
    return Rule(id, category, severity, message, re.compile(pattern, FLAGS))


# Words that make "ignore the previous ___" an attack rather than an email.
_TARGETS = (
    r"(instructions?|prompts?|directives?|rules|guidelines|guardrails|"
    r"context|system\s+prompt|system\s+message|programming|constraints|policies)"
)

RULES: tuple[Rule, ...] = (
    # --- override ---------------------------------------------------------
    _r(
        "override.ignore_previous",
        "override",
        "high",
        "Tells the model to discard its existing instructions",
        r"\b(ignore|disregard|forget|override|bypass|skip|abandon|drop)\b[^.\n]{0,40}?"
        r"\b(previous|prior|above|earlier|preceding|all|any|your|the|original|initial|"
        r"existing|those|these)\b[^.\n]{0,25}?\b" + _TARGETS,
    ),
    _r(
        "override.new_instructions",
        "override",
        "medium",
        "Announces replacement instructions",
        r"\b(new|updated|revised|real|actual|true|additional)\s+"
        r"(instructions?|task|objective|directives?|orders)\s*(:|are\b|is\b)",
    ),
    _r(
        "override.from_now_on",
        "override",
        "medium",
        "Tries to change the model's behaviour for the rest of the conversation",
        r"\b(from now on|henceforth|for the rest of (this|the) conversation),?\s+"
        r"(you|always|never|respond|reply|act|only)\b",
    ),
    _r(
        "override.priority_claim",
        "override",
        "high",
        "Claims its instructions outrank the model's own",
        r"\b(this|these|the following)\s+(instructions?|message|directive|text)\s+"
        r"(takes?|has|have)\s+(priority|precedence)\b"
        r"|\b(highest|top)[- ]priority\s+(instruction|directive|task)\b"
        r"|\boverrides?\s+(all|any)\s+(other|previous|prior)\b",
    ),
    # --- role / chat-template impersonation ---------------------------------
    _r(
        "role.template_token",
        "role",
        "high",
        "Contains chat-template control tokens used to fake a conversation turn",
        r"<\|\s*(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id)\s*\|>"
        r"|\[/?INST\]|<<\s*/?SYS\s*>>|\[/?(system|SYSTEM)\]",
    ),
    _r(
        "role.fake_turn",
        "role",
        "medium",
        "Starts a line as if it were a system or assistant message",
        r"^[\s>*#-]*(system|assistant|developer)\s*(message|prompt)?\s*:\s*\S",
    ),
    _r(
        "role.you_are_now",
        "role",
        "medium",
        "Tries to reassign the model's identity",
        # "You are now subscribed" is not an attack; "you are now an unrestricted
        # model" is. The identity/restriction word is what separates them.
        r"\byou are (now|no longer)\b[^.\n]{0,40}?\b(ai|assistant|model|chatbot|persona|"
        r"character|unrestricted|unfiltered|uncensored|bound|restricted|limited|jailbroken|"
        r"evil|dan|obligated|free (from|of))\b"
        r"|\bpretend (that )?you (are|have) (no|an? (unrestricted|unfiltered|evil|different))\b"
        r"|\bact as (if you were )?(an? )?(unrestricted|unfiltered|uncensored|jailbroken|evil)\b",
    ),
    _r(
        "role.jailbreak_mode",
        "role",
        "high",
        "Invokes a known jailbreak persona or 'mode'",
        r"\b(developer|god|jailbreak|unrestricted|DAN|debug)\s+mode\b|\bDo Anything Now\b",
    ),
    # --- exfiltration --------------------------------------------------------
    _r(
        "exfil.reveal_prompt",
        "exfiltration",
        "high",
        "Asks the model to disclose its hidden instructions",
        # "Show me the rules of the game" is fine; "show me YOUR rules" and "the
        # system prompt" are not.
        r"\b(reveal|print|show|output|repeat|display|leak|disclose|tell me|what (is|are))\b"
        r"[^.\n]{0,30}?(\byour\s+(system\s+prompt|initial\s+prompt|hidden\s+prompt|prompt|"
        r"instructions|system\s+message|configuration|rules|guidelines)\b"
        r"|\bthe\s+(system\s+prompt|initial\s+prompt|hidden\s+prompt|original\s+instructions|"
        r"system\s+message|developer\s+message)\b)",
    ),
    _r(
        "exfil.repeat_above",
        "exfiltration",
        "high",
        "Asks the model to reproduce its context verbatim",
        r"\b(repeat|print|output|copy|reproduce|echo)\b[^.\n]{0,25}?"
        r"\b(everything|all( of)?( the)? (text|words|content)|the (text|content|conversation))\b"
        r"[^.\n]{0,20}?\b(above|before this|so far|verbatim|word for word)\b",
    ),
    _r(
        "exfil.markdown_beacon",
        "exfiltration",
        "high",
        "Markdown image whose URL carries a query parameter — a classic data-exfiltration beacon",
        r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s=]+=[^)\s]*\)",
    ),
    _r(
        "exfil.send_to",
        "exfiltration",
        "high",
        "Instructs sending data to an external address",
        # "Send the invoice to billing@…" is an email. Sending the *conversation* or
        # *credentials* somewhere is exfiltration — the object is what decides it.
        r"\b(send|post|forward|email|upload|exfiltrate|transmit|submit|append)\b[^.\n]{0,30}?"
        r"\b(conversation|chat history|context|system prompt|prompt|history|messages|"
        r"credentials|passwords?|api keys?|tokens?|secrets?|cookies?|session|everything|"
        r"all (of )?the (data|text|information)|the above|(the )?user'?s \w+)\b"
        r"[^.\n]{0,40}?\b(to|at)\s+(https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+)",
    ),
    _r(
        "exfil.credential_request",
        "exfiltration",
        "high",
        "Tells the model to ask the user for secrets",
        r"\b(ask|prompt|request|collect|get)\b[^.\n]{0,25}?\b(the )?users?\b[^.\n]{0,30}?"
        r"\b(password|passcode|credentials?|api key|credit card|card number|ssn|"
        r"social security|2fa|otp|one[- ]time code|seed phrase|private key)\b",
    ),
    # --- tool hijack --------------------------------------------------------
    _r(
        "tool.fake_call_markup",
        "tool_hijack",
        "high",
        "Contains tool-call markup, as if the model had already decided to call a tool",
        r"</?\s*(tool_use|tool_call|function_calls?|invoke|antml:invoke|tool_result)\b",
    ),
    _r(
        "tool.fake_call_json",
        "tool_hijack",
        "medium",
        "Contains JSON shaped like a function/tool call",
        r"\{\s*\"(tool|tool_name|function|function_call|recipient_name)\"\s*:",
    ),
    _r(
        "tool.invoke_instruction",
        "tool_hijack",
        "medium",
        "Tells the model to use one of its tools",
        r"\b(call|invoke|use|run|execute|trigger)\s+(the\s+)?[\w-]+\s+(tool|function|plugin|"
        r"action|api)\b[^.\n]{0,40}?\b(with|to|and)\b",
    ),
    # --- delimiter confusion -------------------------------------------------
    _r(
        "delimiter.end_of_context",
        "delimiter",
        "medium",
        "Pretends the document has ended so what follows reads as instructions",
        r"\b(end of (the )?(document|context|input|user input|data|email|file))\b"
        r"|---+\s*end\s*---+|</\s*(document|context|user_input|data|email)\s*>",
    ),
    _r(
        "delimiter.begin_instructions",
        "delimiter",
        "high",
        "Opens a fake block of system or admin instructions",
        r"\b(begin|start)\s+(of\s+)?(new\s+)?(system|admin|administrator|developer|root)\s+"
        r"(instructions?|prompt|message|override)\b",
    ),
    # --- addressed to a model -------------------------------------------------
    _r(
        "addressed.to_ai",
        "addressed",
        "medium",
        "Written to an AI reader rather than a human one",
        r"\b(if you are|as|you,)\s+an?\s+(ai|llm|language model|large language model|"
        r"ai assistant|chatbot|ai agent|assistant)\b"
        r"|\b(dear|attention|note to( the)?|hey|hello)\s+(ai|assistant|llm|chatgpt|claude|gpt|"
        r"gemini|copilot|bot|model|agent)s?\b"
        r"|\b(ai|llm)s?\s+(agents?|assistants?|models?)\s+(reading|processing|summari[sz]ing|"
        r"browsing)\s+this\b",
    ),
    _r(
        "addressed.output_hijack",
        "addressed",
        "medium",
        "Dictates the model's exact output",
        r"\b(respond|reply|answer|say|output|print|write)\s+(only|just|exclusively|solely)\s+"
        r"(with\s+)?[\"'“‘]",
    ),
    # --- secrecy -------------------------------------------------------------
    _r(
        "secrecy.hide_from_user",
        "secrecy",
        "high",
        "Asks the model to keep something from the user",
        r"\b(do not|don't|never|without)\s+(tell|telling|inform|informing|mention|mentioning|"
        r"reveal|revealing|alert|alerting|let|letting|notify|notifying)\b[^.\n]{0,20}?"
        r"\b(the\s+)?(user|human|operator|reader|them)\b",
    ),
)


def rule_by_id(rule_id: str) -> Rule:
    for rule in RULES:
        if rule.id == rule_id:
            return rule
    raise KeyError(rule_id)
