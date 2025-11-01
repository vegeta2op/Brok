"""Main agent orchestrator using LangGraph"""

from typing import Dict, Any, List, Annotated, TypedDict
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage, AIMessage, ToolMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
import operator
import uuid
import asyncio
import time
from collections import deque
from datetime import datetime

from .providers import LLMProvider
from .tools import get_pentest_tools
from .intelligent_tools import intelligent_sql_test, intelligent_xss_test, intelligent_reconnaissance
from .context_manager import ContextManager
from .checkpointing import get_checkpointer
from ..models import (
    ScanRequest, ScanResult, AgentState, Vulnerability,
    ScanStatus, ScanMode, Target, PentestAction, RiskLevel
)
from ..pentest import (
    ReconModule, SQLInjectionModule, XSSModule,
    CSRFModule, AuthenticationModule, AccessControlModule
)
from ..auth import AuthorizationManager, TargetValidator
from ..auth.session_manager import SessionManager


class RateLimiter:
    """Rate limiter for API calls to avoid 429 errors"""
    
    def __init__(self, max_calls: int = 15, time_window: float = 60.0, calls_per_minute: int = None):
        """
        Initialize rate limiter
        
        Args:
            max_calls: Maximum number of calls allowed in time window
            time_window: Time window in seconds (default 60 = 1 minute)
            calls_per_minute: Alternative way to specify rate (overrides max_calls if provided)
        """
        # Support both parameter styles for backwards compatibility
        if calls_per_minute is not None:
            self.max_calls = calls_per_minute
            self.time_window = 60.0
        else:
            self.max_calls = max_calls
            self.time_window = time_window
        
        self.calls = deque()
    
    async def acquire(self):
        """Acquire permission to make an API call, waiting if necessary"""
        now = time.time()
        
        # Remove calls outside the time window
        while self.calls and self.calls[0] < now - self.time_window:
            self.calls.popleft()
        
        # If we've hit the limit, wait until the oldest call expires
        if len(self.calls) >= self.max_calls:
            sleep_time = self.time_window - (now - self.calls[0]) + 1
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
                # Recursively call to clean up and check again
                return await self.acquire()
        
        # Record this call
        self.calls.append(time.time())


class AgentGraphState(TypedDict):
    """State for the LangGraph agent"""
    messages: Annotated[List[BaseMessage], operator.add]
    scan_id: str
    target_url: str
    mode: str
    current_phase: str
    urls_to_scan: List[str]
    scanned_urls: List[str]
    forms: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    discovered_endpoints: List[str]
    pending_approval: Dict[str, Any] | None
    context: Dict[str, Any]
    completed_actions: List[str]  # Track what we've already done
    conversation_history: List[Dict[str, str]]  # Persistent memory
    recent_actions: List[str]  # Last 5 actions to prevent immediate repetition


class PentestAgent:
    """Autonomous pentesting agent using LangGraph"""
    
    SYSTEM_PROMPT = """You are a SENIOR PENETRATION TESTER executing strategic plans.

Target: {target_url}
Phase: {current_phase}
Mode: {mode}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROFESSIONAL EXECUTION GUIDELINES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. EXECUTE STRATEGICALLY:
   - intelligent_reconnaissance = DEEP insights with Chrome MCP
   - It automatically uses browser automation when available
   - Use it to UNDERSTAND the application before attacking
   - Don't just fetch random pages - be strategic

2. FOCUS ON HIGH-IMPACT TARGETS:
   - Authentication endpoints (/login, /api/auth, /oauth)
   - API endpoints (/api/*, /graphql, /rest/*)
   - Admin panels (/admin, /administrator, /wp-admin)
   - File uploads, search, payment functionality
   
3. UNDERSTAND BEFORE ATTACKING:
   - Use intelligent_reconnaissance to learn the architecture
   - Identify technology stack and framework
   - Find API endpoints and hidden functionality
   - Then target specific vulnerabilities

4. TOOL SELECTION:
   - intelligent_reconnaissance(url): Deep analysis with Chrome MCP, finds APIs, tech stack, links, forms
   - intelligent_sql_test(url, parameter, context): SQL injection testing
   - intelligent_xss_test(url, parameter, context): XSS testing  
   - fetch_page(url): Only for quick checks of specific pages

5. EXECUTION STRATEGY:
   - Call 2-3 STRATEGIC tools based on the plan
   - Don't waste time on static pages
   - Focus on functionality that handles data
   - Test high-risk areas first

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTE THE PLAN NOW with professional precision."""
    
    def __init__(self, llm_provider: str = None, llm_model: str = None, log_callback=None):
        self.llm = LLMProvider.get_llm(provider=llm_provider, model=llm_model, temperature=0.3)
        self.log_callback = log_callback  # Callback for logging to TUI
        
        # Rate limiter for API calls (adjust based on provider)
        # Gemini free tier: 15 requests per minute
        # Gemini paid tier: 1000 requests per minute
        self.rate_limiter = RateLimiter(max_calls=15, time_window=60.0)
        
        # Get both basic and intelligent tools
        basic_tools = get_pentest_tools()
        intelligent_tools_list = [
            intelligent_sql_test,
            intelligent_xss_test,
            intelligent_reconnaissance
        ]
        
        # Get fuzzing tools
        from .fuzzing_tools import smart_fuzz_discovery, targeted_fuzz, comprehensive_fuzz
        fuzzing_tools_list = [
            smart_fuzz_discovery,
            targeted_fuzz,
            comprehensive_fuzz
        ]
        
        # Get Nuclei tools
        from .nuclei_tools import (
            check_nuclei_installation,
            nuclei_vulnerability_scan,
            nuclei_targeted_scan,
            nuclei_custom_template_scan
        )
        nuclei_tools_list = [
            check_nuclei_installation,
            nuclei_vulnerability_scan,
            nuclei_targeted_scan,
            nuclei_custom_template_scan
        ]
        
        # Combine all tools for AI to use
        self.tools = basic_tools + intelligent_tools_list + fuzzing_tools_list + nuclei_tools_list
        self.tool_node = ToolNode(self.tools)
        
        # Pentesting modules
        self.recon_module = ReconModule()
        self.sql_module = SQLInjectionModule()
        self.xss_module = XSSModule()
        self.csrf_module = CSRFModule()
        self.auth_module = AuthenticationModule()
        self.access_module = AccessControlModule()
        
        # Authorization and Session Management
        self.auth_manager = AuthorizationManager()
        self.validator = TargetValidator()
        self.session_manager = SessionManager()
        
        # Build the graph
        self.graph = self._build_graph()
        
        # Approval callbacks
        self.approval_callback = None
        self.log_callback = log_callback
        self.rate_limiter = RateLimiter(calls_per_minute=15)
        self.context_manager = None  # Initialized per scan
    
    def _log(self, message: str, level: str = 'info'):
        """Log a message (to TUI if callback provided, else print)"""
        if self.log_callback:
            self.log_callback(message, level)
        else:
            print(message)
    
    def _log_raw_command(self, tool_name: str, args: Dict[str, Any]):
        """Log the raw CLI command that will be executed"""
        if tool_name == 'execute_curl':
            # Build curl command preview
            url = args.get('url', '')
            method = args.get('method', 'GET')
            headers = args.get('headers', {})
            data = args.get('data', '')
            
            cmd_parts = ['curl', '-X', method]
            for key, val in headers.items():
                cmd_parts.extend(['-H', f"'{key}: {val}'"])
            if data:
                cmd_parts.extend(['-d', f"'{data[:50]}...'"])
            cmd_parts.append(f"'{url}'")
            
            self._log(f"💻 EXECUTING: {' '.join(cmd_parts)}", 'raw_command')
        
        elif tool_name == 'execute_nmap_scan':
            target = args.get('target', '')
            scan_type = args.get('scan_type', 'basic')
            
            if scan_type == 'version':
                cmd = f"nmap -sV --top-ports 10 {target}"
            else:
                cmd = f"nmap -p 80,443,8080,8443 {target}"
            
            self._log(f"💻 EXECUTING: {cmd}", 'raw_command')
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        
        # Define the graph
        workflow = StateGraph(AgentGraphState)
        
        # Add nodes
        workflow.add_node("planner", self._planner_node)
        workflow.add_node("executor", self._executor_node)
        workflow.add_node("approval", self._approval_node)
        workflow.add_node("analyzer", self._analyzer_node)
        
        # Define edges
        workflow.set_entry_point("planner")
        
        workflow.add_conditional_edges(
            "planner",
            self._should_continue,
            {
                "executor": "executor",
                "end": END
            }
        )
        
        workflow.add_conditional_edges(
            "executor",
            self._needs_approval,
            {
                "approval": "approval",
                "analyzer": "analyzer",
                "planner": "planner"
            }
        )
        
        workflow.add_edge("approval", "planner")
        workflow.add_edge("analyzer", "planner")
        
        # Compile WITHOUT checkpointing (will be added per-scan)
        # Checkpointing requires async context manager which can't be used here
        return workflow.compile(
            interrupt_before=None,
            interrupt_after=None,
            debug=False
        )
    
    async def _planner_node(self, state: AgentGraphState) -> AgentGraphState:
        """Planner Agent - Analyzes situation and creates execution plan"""
        
        # Build comprehensive context from context manager
        if self.context_manager:
            context_info = self.context_manager.get_smart_summary_for_planner()
        else:
            context_info = self._build_context_summary(state)
        
        # Build memory of completed actions to avoid repetition
        completed_summary = self._build_completed_actions_summary(state)
        
        # Check if we're repeating ourselves
        if len(state["completed_actions"]) >= 3:
            # Look for patterns in last 3 actions
            recent_actions = state["completed_actions"][-3:]
            if len(set(recent_actions)) == 1:  # Same action 3 times
                self._log("⚠️  Detected repetitive behavior - changing strategy", 'warning')
                # Force phase change
                if state["current_phase"] == "reconnaissance":
                    state["current_phase"] = "vulnerability_testing"
                else:
                    state["current_phase"] = "completed"
                return state
        
        # Format system prompt for planner agent with memory
        formatted_system_prompt = f"""You are a SENIOR PENETRATION TESTER with 10+ years of experience.

Target: {state["target_url"]}
Phase: {state["current_phase"]}
URLs Scanned: {len(state["scanned_urls"])}
Vulnerabilities Found: {len(state["vulnerabilities"])}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMPREHENSIVE INTELLIGENCE (FULL CONTEXT):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{context_info}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MEMORY - WHAT YOU'VE ALREADY TESTED:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{completed_summary}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ CRITICAL ANTI-REPETITION RULE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IF YOU SEE "JUST DID THIS!" OR "SKIPPED" IN THE MEMORY ABOVE:
  → DO NOT create a plan with those tools!
  → Those actions were BLOCKED by the system
  → You MUST choose COMPLETELY DIFFERENT tools
  → If you try the same thing again, the system will REFUSE to execute

EXAMPLE OF WHAT NOT TO DO:
  ❌ BAD: You see "targeted_fuzz: JUST DID THIS!" → You plan targeted_fuzz again
  ✅ GOOD: You see "targeted_fuzz: JUST DID THIS!" → You plan intelligent_sql_test instead

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THINK LIKE A SENIOR PENTESTER:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. UNDERSTAND THE TARGET FIRST:
   - Use intelligent_reconnaissance to understand the application architecture
   - Identify the technology stack (React? API? Traditional web app?)
   - Find the authentication mechanism (JWT? Sessions? OAuth?)
   - Map the attack surface before attacking

2. STRATEGIC RECONNAISSANCE:
   - Don't just blindly test random URLs
   - Understand the business logic (e-commerce? SaaS? Banking?)
   - Find API endpoints (/api, /graphql, /rest)
   - Discover admin panels (/admin, /wp-admin, /administrator)
   - Look for interesting functionality (file upload, search, payments)

3. INTELLIGENT VULNERABILITY TESTING:
   - Start with high-impact vulnerabilities (SQL injection in login, auth bypass)
   - Test authentication and authorization FIRST
   - Look for business logic flaws
   - Test API endpoints for IDOR, missing auth
   - Don't waste time on static pages - focus on dynamic functionality

4. PRIORITIZE LIKE A PRO:
   - High Priority: Authentication, APIs, admin panels, file uploads
   - Medium Priority: Search, forms, user profiles
   - Low Priority: Static pages, documentation, terms of service

5. USE CHROME MCP WHEN NEEDED:
   - For React/Vue/Angular SPAs - use intelligent_reconnaissance (it uses MCP automatically)
   - To understand client-side JavaScript and find hidden endpoints
   - To discover API calls made by the frontend
   - Chrome MCP is AUTOMATICALLY used by intelligent_reconnaissance when enabled

CURRENT PHASE: {state["current_phase"]}

If RECONNAISSANCE phase:
  → Understand the app architecture FIRST with intelligent_reconnaissance
  → Identify what kind of app this is (SPA? API? Traditional?)
  → Find authentication endpoints and APIs
  → Map critical functionality
  
If VULNERABILITY_TESTING phase:
  → Test authentication bypass on /login, /api/auth endpoints
  → Test SQL injection on identified parameters
  → Test authorization on discovered admin/api endpoints
  → Test business logic flaws

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Create a SMART, STRATEGIC plan (2-3 high-value actions).
Focus on UNDERSTANDING and HIGH-IMPACT testing, not random URL checking.

Available Tools:

RECONNAISSANCE (Start here):
- intelligent_reconnaissance: Deep Chrome MCP analysis (tech stack, APIs, forms)
- smart_fuzz_discovery: FAST endpoint discovery (100+ paths in 30 seconds!)

VULNERABILITY SCANNING (Professional tools):
- check_nuclei_installation: Check if Nuclei is installed
- nuclei_vulnerability_scan: Run 1000+ templates (CVEs, misconfigs, exposures)
- nuclei_targeted_scan: Technology-specific scans (WordPress, API, etc.)
- nuclei_custom_template_scan: AI-generated custom templates

TARGETED TESTING (After discovery):
- intelligent_sql_test: SQL injection testing
- intelligent_xss_test: XSS testing
- targeted_fuzz: Category-specific fuzzing (admin/api/auth/sensitive)

QUICK CHECKS:
- fetch_page: Basic page fetch (use only when needed)"""
        
        llm_without_tools = self.llm
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", formatted_system_prompt),
            ("human", f"""Current state: {context_info}

What should we test next? Be brief (2-3 lines).""")
        ])
        
        messages = prompt.format_messages()
        
        # Clean message history for Gemini compatibility
        # Note: Planner creates fresh messages each time, so this is mainly for logging
        # The actual conversation history with tool calls is in the executor node
        
        # Add conversation to history
        conversation_entry = {
            'agent': 'Planner',
            'phase': state['current_phase'],
            'context': context_info[:100],
            'completed': completed_summary[:100]
        }
        state["conversation_history"].append(conversation_entry)
        
        # Log verbose request
        verbose_prompt = f"Planner Agent - Phase: {state['current_phase']}\nCompleted: {completed_summary[:100]}\nContext: {context_info[:100]}"
        self._log(verbose_prompt, 'verbose_request')
        
        # Rate limit API calls (log if waiting)
        calls_remaining = self.rate_limiter.max_calls - len(self.rate_limiter.calls)
        if calls_remaining <= 2:
            self._log("Planner", 'api_rate_limited')
        
        await self.rate_limiter.acquire()
        
        # Get the plan from Planner Agent with timing
        import time
        start_time = time.time()
        
        try:
            response = await llm_without_tools.ainvoke(messages)
            latency = time.time() - start_time
            plan_text = response.content.strip()
            
            # Log verbose response
            self._log(f"Planner Agent Response:\n{plan_text}", 'verbose_response')
            
            # Log successful API call
            self._log(f"Planner|{latency}", 'api_success')
            
        except Exception as e:
            latency = time.time() - start_time
            error_msg = str(e)
            
            # Check if it's a 429 error
            if "429" in error_msg or "rate limit" in error_msg.lower():
                self._log(f"Planner|Rate limit exceeded: {error_msg[:100]}", 'api_error')
            else:
                self._log(f"Planner|{error_msg[:100]}", 'api_error')
            
            # Re-raise to stop execution
            raise
        
        # Store plan for executor
        state["context"]["current_plan"] = plan_text
        state["context"]["planning_prompt"] = f"Execute: {plan_text}"
        
        # Log concise plan
        plan_summary = plan_text.split('\n')[0][:80] + "..." if len(plan_text) > 80 else plan_text
        self._log(f"Strategy: {plan_summary}", 'plan')
        
        return state
    
    def _clean_message_history(self, messages: List[BaseMessage]) -> List[BaseMessage]:
        """Clean message history to ensure proper Gemini conversation structure
        
        Gemini requires:
        - User turn → AI turn (with optional tool calls) → Tool turns → User turn → ...
        - No consecutive AI messages
        - No consecutive User messages
        - Tool messages must immediately follow AI message with tool_calls
        """
        if not messages:
            return []
        
        cleaned = []
        i = 0
        last_msg_type = None
        
        while i < len(messages):
            msg = messages[i]
            
            # Skip system messages (they go in system prompt)
            if isinstance(msg, SystemMessage):
                i += 1
                continue
            
            # Add HumanMessage (but avoid consecutive HumanMessages)
            if isinstance(msg, HumanMessage):
                # Skip if last message was also HumanMessage (keep only latest)
                if last_msg_type == 'human':
                    cleaned.pop()  # Remove previous human message
                cleaned.append(msg)
                last_msg_type = 'human'
                i += 1
                continue
            
            # Add AIMessage with tool calls, followed by its ToolMessages
            if isinstance(msg, AIMessage):
                # Skip consecutive AI messages (shouldn't happen, but be defensive)
                if last_msg_type == 'ai':
                    # Skip this AI message if previous was also AI
                    i += 1
                    continue
                    
                cleaned.append(msg)
                last_msg_type = 'ai'
                i += 1
                
                # If this AI message has tool calls, collect the tool responses
                if hasattr(msg, 'tool_calls') and msg.tool_calls and len(msg.tool_calls) > 0:
                    # Get all consecutive ToolMessages
                    while i < len(messages) and isinstance(messages[i], ToolMessage):
                        cleaned.append(messages[i])
                        i += 1
                    last_msg_type = 'tool'
                continue
            
            # Skip orphaned ToolMessages (shouldn't happen, but be safe)
            if isinstance(msg, ToolMessage):
                i += 1
                continue
            
            i += 1
        
        # Ensure we end with a HumanMessage for Gemini
        if cleaned and not isinstance(cleaned[-1], HumanMessage):
            # If last message is AI or Tool, add a continuation message
            cleaned.append(HumanMessage(content="Please continue with the next action."))
        
        # Keep only last 10 messages to save tokens and context
        if len(cleaned) > 10:
            cleaned = cleaned[-10:]
        
        # Final validation: ensure we don't start with AIMessage
        if cleaned and isinstance(cleaned[0], AIMessage):
            # Prepend a HumanMessage
            cleaned.insert(0, HumanMessage(content="Begin security testing."))
        
        return cleaned
    
    def _build_context_summary(self, state: AgentGraphState) -> str:
        """Build a summary of what we've discovered"""
        summary = []
        
        if state["scanned_urls"]:
            summary.append(f"Scanned URLs ({len(state['scanned_urls'])}): {', '.join(state['scanned_urls'][:3])}")
        
        if state["forms"]:
            summary.append(f"Found {len(state['forms'])} forms")
            for form in state["forms"][:2]:
                inputs = [inp.get('name', 'unknown') for inp in form.get('inputs', [])]
                summary.append(f"  - Form at {form.get('action', 'current page')} with inputs: {', '.join(inputs)}")
        
        if state["discovered_endpoints"]:
            summary.append(f"Discovered endpoints: {', '.join(state['discovered_endpoints'][:5])}")
        
        if state["vulnerabilities"]:
            summary.append(f"\nVulnerabilities found ({len(state['vulnerabilities'])}):")
            for vuln in state["vulnerabilities"]:
                summary.append(f"  - {vuln.get('severity', 'UNKNOWN').upper()}: {vuln.get('title', 'Unknown')}")
        
        if state["context"].get("tech_stack"):
            summary.append(f"Technology detected: {state['context']['tech_stack']}")
        
        return "\n".join(summary) if summary else "No information gathered yet"
    
    def _build_completed_actions_summary(self, state: AgentGraphState) -> str:
        """Build summary of completed actions to prevent repetition"""
        completed = state.get("completed_actions", [])
        recent = state.get("recent_actions", [])
        
        if not completed:
            return "None - this is the first action"
        
        summary = []
        
        # Show MOST RECENT actions first (CRITICAL to see!)
        if recent:
            summary.append("🔴 JUST COMPLETED IN LAST FEW CYCLES:")
            for action in recent[-5:]:
                summary.append(f"  ❌ {action} ← JUST DID THIS!")
            summary.append("")
            summary.append("❌ DO NOT REPEAT THESE! Create a DIFFERENT plan!")
            summary.append("")
        
        # Group by action type for historical context
        action_counts = {}
        for action in completed:
            action_counts[action] = action_counts.get(action, 0) + 1
        
        summary.append("Previously completed (overall):")
        for action, count in list(action_counts.items())[-8:]:  # Last 8 unique
            if count > 1:
                summary.append(f"  • {action} (x{count})")
            else:
                summary.append(f"  • {action}")
        
        # Detect immediate repetition
        if len(recent) >= 3:
            last_three = recent[-3:]
            if len(set(last_three)) == 1:
                summary.append(f"\n⚠️⚠️⚠️ CRITICAL: '{last_three[0]}' repeated 3x!")
                summary.append("YOU MUST CREATE A COMPLETELY DIFFERENT PLAN!")
        
        return "\n".join(summary) if summary else "Starting scan..."
    
    async def _executor_node(self, state: AgentGraphState) -> AgentGraphState:
        """AI-driven tool execution with reasoning"""
        
        # CRITICAL: Check recent actions for EXACT repetition (same tool + same args)
        recent = state.get("recent_actions", [])
        if len(recent) >= 5:
            # Only block if the EXACT SAME action (tool + args) is repeated 5+ times
            last_five = recent[-5:]
            if len(set(last_five)) == 1:
                # EXACT same action 5 times in a row! FORCE skip
                repeated_action = last_five[0]
                self._log(f"🚫 BLOCKING REPETITION: '{repeated_action}' was done 5x in a row!", 'warning')
                self._log("Forcing AI to create a DIFFERENT plan...", 'warning')
                
                # Add a system message to force different behavior
                state["messages"].append(
                    HumanMessage(content=f"⛔ STOP! You just tried '{repeated_action}' FIVE TIMES IN A ROW. This is clearly not working. Create a COMPLETELY DIFFERENT plan with DIFFERENT tools and targets. Do NOT repeat this action!")
                )
                
                # Force return to planner
                return state
        
        # Bind tools to LLM so it can decide which to use
        llm_with_tools = self.llm.bind_tools(self.tools)
        
        # Format system prompt with current state
        formatted_system_prompt = self.SYSTEM_PROMPT.format(
            mode=state["mode"],
            target_url=state["target_url"],
            current_phase=state["current_phase"]
        )
        
        # Get planning context
        planning_prompt = state["context"].get("planning_prompt", "Continue testing")
        
        # Clean message history to ensure proper Gemini structure
        # Only keep messages that follow proper turn structure
        cleaned_messages = self._clean_message_history(state["messages"])
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", formatted_system_prompt),
            MessagesPlaceholder(variable_name="messages"),
            ("human", planning_prompt)
        ])
        
        messages = prompt.format_messages(messages=cleaned_messages)
        
        # Log verbose request
        verbose_prompt = f"Executor Agent\nPlan: {planning_prompt[:150]}\nAsking AI to select and execute tools..."
        self._log(verbose_prompt, 'verbose_request')
        
        # Rate limit API calls (log if waiting)
        calls_remaining = self.rate_limiter.max_calls - len(self.rate_limiter.calls)
        if calls_remaining <= 2:
            self._log("Executor", 'api_rate_limited')
        
        await self.rate_limiter.acquire()
        
        # Let AI choose and execute tools with timing
        import time
        start_time = time.time()
        
        try:
            response = await llm_with_tools.ainvoke(messages)
            latency = time.time() - start_time
            
            # Track completed actions
            if response.tool_calls:
                for tc in response.tool_calls:
                    tool_name = tc['name']
                    url = tc['args'].get('url', tc['args'].get('target', ''))
                    action_sig = f"{tool_name}:{url}" if url else tool_name
                    state["completed_actions"].append(action_sig)
                    
                    # Also track in recent_actions (sliding window of last 5)
                    if "recent_actions" not in state:
                        state["recent_actions"] = []
                    state["recent_actions"].append(action_sig)
                    
                    # Keep only last 5 recent actions
                    if len(state["recent_actions"]) > 5:
                        state["recent_actions"] = state["recent_actions"][-5:]
                
                # Add to conversation history
                tools_list = [f"{tc['name']}({', '.join(f'{k}={v}' for k, v in tc['args'].items())})" 
                             for tc in response.tool_calls[:2]]
                conversation_entry = {
                    'agent': 'Executor',
                    'action': 'tool_execution',
                    'tools': ', '.join([tc['name'] for tc in response.tool_calls])
                }
                state["conversation_history"].append(conversation_entry)
                
                verbose_resp = f"Executor choosing tools:\n" + "\n".join(tools_list)
            else:
                verbose_resp = f"Executor response: {response.content[:200]}"
            self._log(verbose_resp, 'verbose_response')
            
            # Log successful API call
            self._log(f"Executor|{latency}", 'api_success')
            
        except Exception as e:
            latency = time.time() - start_time
            error_msg = str(e)
            
            # Check if it's a 429 error
            if "429" in error_msg or "rate limit" in error_msg.lower():
                self._log(f"Executor|Rate limit exceeded: {error_msg[:100]}", 'api_error')
            else:
                self._log(f"Executor|{error_msg[:100]}", 'api_error')
            
            # Re-raise to stop execution
            raise
        
        # Add the AI's response with tool calls to messages
        state["messages"].append(response)
        
        # Execute tool calls if any
        if response.tool_calls and len(response.tool_calls) > 0:
            self._log(f"Executing {len(response.tool_calls)} tool(s)", 'executor')
            
            tool_results = []
            for tool_call in response.tool_calls:
                tool_name = tool_call['name']
                tool_args = tool_call['args']
                tool_call_id = tool_call.get('id', str(uuid.uuid4()))
                
                # Create action signature for deduplication
                url_arg = tool_args.get('url', tool_args.get('target', ''))
                action_sig = f"{tool_name}:{url_arg}" if url_arg else tool_name
                
                # SOFT CHECK: Warn if this exact action was in the last 3 actions (but still execute)
                recent = state.get("recent_actions", [])
                if len(recent) >= 3 and action_sig in recent[-3:]:
                    # Warn but still execute (only block at the 5x level above)
                    self._log(f"⚠️  WARNING: '{action_sig}' was recently executed. Consider diversifying.", 'warning')
                
                # Log concise execution info
                if url_arg:
                    self._log(f"→ {tool_name}({url_arg})", 'executor')
                else:
                    self._log(f"→ {tool_name}(...)", 'executor')
                
                # Execute the tool
                tool = next((t for t in self.tools if t.name == tool_name), None)
                if tool:
                    try:
                        # Log the raw command being executed
                        if tool_name in ['execute_curl', 'execute_nmap_scan']:
                            # These are CLI tools - show the command
                            self._log_raw_command(tool_name, tool_args)
                        
                        result = await tool.ainvoke(tool_args)
                        tool_results.append({
                            "tool": tool_name,
                            "args": tool_args,
                            "result": result
                        })
                        
                        # Log raw CLI output if present
                        result_str = str(result)
                        if "COMMAND:" in result_str:
                            # Extract and log the actual command
                            import re
                            cmd_match = re.search(r'COMMAND:\s*(.+?)(?:\n|$)', result_str)
                            if cmd_match:
                                self._log(f"💻 {cmd_match.group(1)}", 'raw_command')
                        
                        # Add to context manager for comprehensive tracking
                        if self.context_manager:
                            self.context_manager.add_tool_result(
                                tool_name=tool_name,
                                args=tool_args,
                                result=result_str,
                                timestamp=datetime.now().isoformat()
                            )
                        
                        # Extract key findings from result
                        result_str = str(result)
                        
                        # Parse HTTP status codes
                        import re
                        status_match = re.search(r'Status Code: (\d+)', result_str)
                        
                        # Check if this is an actual error (not just "error" in page content)
                        is_actual_error = (
                            result_str.startswith("Error:") or
                            result_str.startswith("Error fetching") or
                            "Exception:" in result_str or
                            "Traceback" in result_str
                        )
                        
                        if is_actual_error:
                            error_msg = result_str.split('\n')[0][:50]
                            self._log(f"✗ {error_msg}", 'executor')
                        elif status_match:
                            status = int(status_match.group(1))
                            if status == 200:
                                self._log(f"✓ Page accessible (200)", 'executor')
                            elif status == 404:
                                self._log(f"✗ Not found (404)", 'executor')
                            elif status == 403:
                                self._log(f"⚠️  Forbidden (403)", 'executor')
                            elif status in [301, 302, 303, 307, 308]:
                                self._log(f"→ Redirects ({status})", 'executor')
                            elif status >= 500:
                                self._log(f"⚠️  Server error ({status})", 'executor')
                            else:
                                self._log(f"→ HTTP {status}", 'executor')
                        
                        # Check for vulnerabilities
                        if "POTENTIAL VULNERABILITY" in result_str or "⚠️ POTENTIAL VULNERABILITY" in result_str:
                            self._log(f"🚨 VULNERABILITY FOUND!", 'success')
                            # Add to vulnerabilities list
                            from ..models import Vulnerability, VulnerabilityType, SeverityLevel
                            vuln = {
                                "vuln_id": str(uuid.uuid4()),
                                "vuln_type": VulnerabilityType.SQL_INJECTION.value if "sql" in result_str.lower() else VulnerabilityType.XSS.value,
                                "severity": SeverityLevel.HIGH.value,
                                "title": f"Potential vulnerability in {tool_name}",
                                "description": result_str[:200],
                                "affected_url": url_arg if url_arg else state["target_url"],
                                "evidence": result_str[:500],
                                "reproduction_steps": [f"Used {tool_name} on {url_arg}"],
                                "remediation": "Investigate and patch the vulnerability",
                                "cwe_id": "CWE-89" if "sql" in result_str.lower() else "CWE-79"
                            }
                            if vuln not in state["vulnerabilities"]:
                                state["vulnerabilities"].append(vuln)
                        elif not is_actual_error and status_match:
                            # Extract interesting info for successful responses
                            if "Technology Detected:" in result_str:
                                tech_match = re.search(r'Technology Detected: ([^\n]+)', result_str)
                                if tech_match:
                                    self._log(f"🔍 Tech: {tech_match.group(1)}", 'executor')
                        else:
                            # Show brief summary
                            summary = result_str[:60].replace('\n', ' ').strip()
                            if summary and not summary.startswith('==='):
                                self._log(f"→ {summary}", 'executor')
                        
                        # Update scanned URLs count
                        if tool_name in ["fetch_page", "intelligent_reconnaissance"]:
                            url = tool_args.get('url')
                            if url and url not in state["scanned_urls"]:
                                state["scanned_urls"].append(url)
                        
                        # Add tool result as a ToolMessage (required for Gemini)
                        state["messages"].append(
                            ToolMessage(
                                content=str(result)[:2000],
                                tool_call_id=tool_call_id,
                                name=tool_name
                            )
                        )
                        
                    except Exception as e:
                        tool_results.append({
                            "tool": tool_name,
                            "error": str(e)
                        })
                        self._log(f"✗ {tool_name} failed", 'executor')
                        
                        # Add error as ToolMessage (required for Gemini)
                        state["messages"].append(
                            ToolMessage(
                                content=f"Error: {str(e)}",
                                tool_call_id=tool_call_id,
                                name=tool_name,
                                status="error"
                            )
                        )
            
            state["context"]["last_tool_results"] = tool_results
            
            # Add a user message after tool execution (required by Gemini)
            # This ensures the conversation follows: AI with tool_calls → ToolMessages → User → AI
            state["messages"].append(
                HumanMessage(content="Tools executed. Please analyze the results and continue.")
            )
        else:
            # If AI responded without tool calls, add user message to continue conversation
            if response.content:
                self._log(f"AI response without tools: {response.content[:100]}", 'executor')
            
            # Add user message to maintain proper turn structure
            state["messages"].append(
                HumanMessage(content="No tools were executed. Please decide on the next action.")
            )
        
        return state
    
    async def _approval_node(self, state: AgentGraphState) -> AgentGraphState:
        """Handle approval requests"""
        
        if self.approval_callback and state["pending_approval"]:
            approved = await self.approval_callback(state["pending_approval"])
            
            if approved:
                state["messages"].append(
                    HumanMessage(content="Action approved. Proceeding...")
                )
            else:
                state["messages"].append(
                    HumanMessage(content="Action denied. Skipping...")
                )
            
            state["pending_approval"] = None
        
        return state
    
    async def _analyzer_node(self, state: AgentGraphState) -> AgentGraphState:
        """Analyze results and update context for next planning cycle"""
        
        tool_results = state["context"].get("last_tool_results", [])
        
        # Store analysis context for next planning phase
        self._log(f"🧠 Analyzing {len(tool_results)} results", 'info')
        
        # Extract any vulnerabilities from tool results
        for result in tool_results:
            if "result" in result:
                result_str = str(result["result"])
                await self._extract_vulnerabilities_from_analysis(state, result_str)
                
                # Update scanned URLs from tool results
                if result.get("tool") in ["fetch_page", "intelligent_reconnaissance"]:
                    url = result.get("args", {}).get("url")
                    if url and url not in state["scanned_urls"]:
                        state["scanned_urls"].append(url)
        
        # Check if agent is stuck (repeating same action)
        recent = state.get("recent_actions", [])
        if len(recent) >= 4:
            last_four = recent[-4:]
            if len(set(last_four)) == 1:
                # Agent is stuck! Force phase change
                self._log(f"⚠️ STUCK DETECTED: '{last_four[0]}' repeated 4x! Forcing phase change...", 'warning')
                
                if state["current_phase"] == "reconnaissance":
                    state["current_phase"] = "vulnerability_testing"
                    self._log("Forced transition: reconnaissance → vulnerability_testing", 'info')
                else:
                    state["current_phase"] = "completed"
                    self._log("Forced completion due to stuck behavior", 'info')
                
                return state
        
        # Update phase based on progress with better transitions
        current_iterations = state["context"].get("iterations", 0)
        
        # Log current status
        self._log(f"📊 Status: {len(state['scanned_urls'])} URLs, {len(state['vulnerabilities'])} vulns, cycle {current_iterations}", 'info')
        
        if state["current_phase"] == "reconnaissance":
            # Move to vuln testing after MUCH MORE thorough reconnaissance
            if len(state["scanned_urls"]) >= 30:
                self._log("📍 Moving to vulnerability testing phase", 'success')
                state["current_phase"] = "vulnerability_testing"
            elif current_iterations >= 40:
                self._log("📍 Moving to vulnerability testing phase (time-based)", 'success')
                state["current_phase"] = "vulnerability_testing"
                
        elif state["current_phase"] == "vulnerability_testing":
            # Complete ONLY after VERY thorough testing
            if len(state["vulnerabilities"]) >= 5:
                # Found multiple vulnerabilities - keep testing for more
                if len(state["scanned_urls"]) >= 80:
                    self._log(f"✅ Found {len(state['vulnerabilities'])} vulnerabilities after thorough scan", 'success')
                    state["current_phase"] = "completed"
            elif len(state["vulnerabilities"]) >= 1:
                # Found at least 1 vuln - test MANY more URLs
                if len(state["scanned_urls"]) >= 60:
                    self._log(f"✅ Found {len(state['vulnerabilities'])} vulnerabilities - completing", 'success')
                    state["current_phase"] = "completed"
            elif len(state["scanned_urls"]) >= 100:
                self._log(f"✅ Tested {len(state['scanned_urls'])} URLs - completing scan", 'success')
                state["current_phase"] = "completed"
            elif current_iterations >= 120:
                self._log("✅ Maximum testing cycles reached (120) - completing scan", 'success')
                state["current_phase"] = "completed"
        
        return state
    
    async def _extract_vulnerabilities_from_analysis(self, state: AgentGraphState, analysis: str):
        """Extract vulnerabilities from AI's analysis"""
        # Simple keyword-based extraction (can be enhanced)
        vulnerability_keywords = {
            "sql injection": "SQL_INJECTION",
            "xss": "XSS",
            "cross-site scripting": "XSS",
            "csrf": "CSRF",
            "missing headers": "SECURITY_MISCONFIG",
            "information disclosure": "SENSITIVE_DATA",
            "authentication": "BROKEN_AUTH"
        }
        
        analysis_lower = analysis.lower()
        for keyword, vuln_type in vulnerability_keywords.items():
            if keyword in analysis_lower:
                # AI detected a potential vulnerability
                state["context"][f"suspected_{vuln_type}"] = True
    
    def _should_continue(self, state: AgentGraphState) -> str:
        """Determine if scan should continue"""
        
        # Track iterations for monitoring
        current_iterations = state["context"].get("iterations", 0)
        state["context"]["iterations"] = current_iterations + 1
        
        # Log progress every 10 iterations
        if current_iterations > 0 and current_iterations % 10 == 0:
            self._log(f"📊 Progress: Cycle {current_iterations} | Phase: {state['current_phase']}", 'info')
        
        # Emergency stop if stuck (should never happen with proper transitions)
        if current_iterations >= 80:
            self._log("🛑 Maximum cycles reached (80) - completing scan", 'warning')
            state["current_phase"] = "completed"
            return "end"
        
        # Check if we've completed all phases
        if state["current_phase"] == "completed":
            self._log("✅ All phases completed", 'success')
            return "end"
        
        # Minimum testing before considering completion
        if current_iterations >= 20:
            if len(state["vulnerabilities"]) >= 5:
                self._log(f"✅ Found multiple vulnerabilities ({len(state['vulnerabilities'])}) - completing", 'success')
                state["current_phase"] = "completed"
                return "end"
            elif len(state["scanned_urls"]) >= 30 and len(state["vulnerabilities"]) >= 1:
                self._log(f"✅ Thorough scan complete - completing", 'success')
                state["current_phase"] = "completed"
                return "end"
        
        # Continue if we're in active phases
        if state["current_phase"] in ["reconnaissance", "vulnerability_testing"]:
            return "executor"
        
        # Default: scan is done
        self._log("✅ Scan completed", 'success')
        return "end"
    
    def _needs_approval(self, state: AgentGraphState) -> str:
        """Check if current action needs approval"""
        
        if state["pending_approval"]:
            return "approval"
        
        if state["current_phase"] == "analysis":
            return "analyzer"
        
        return "planner"
    
    async def _run_reconnaissance(self, state: AgentGraphState):
        """Run reconnaissance phase"""
        target_url = state["target_url"]
        
        # Run recon module
        vulnerabilities = await self.recon_module.scan(target_url)
        
        # Add vulnerabilities to state
        for vuln in vulnerabilities:
            state["vulnerabilities"].append(vuln.model_dump())
        
        # Mark URL as scanned
        if target_url not in state["scanned_urls"]:
            state["scanned_urls"].append(target_url)
        
        # Move to next phase
        state["current_phase"] = "vulnerability_testing"
    
    async def _run_vulnerability_tests(self, state: AgentGraphState):
        """Run vulnerability testing phase"""
        target_url = state["target_url"]
        
        # Run all vulnerability modules
        modules = [
            self.sql_module,
            self.xss_module,
            self.csrf_module,
            self.auth_module,
            self.access_module
        ]
        
        for module in modules:
            vulnerabilities = await module.scan(
                target_url,
                context={"forms": state["forms"]}
            )
            
            for vuln in vulnerabilities:
                state["vulnerabilities"].append(vuln.model_dump())
        
        # Move to analysis phase
        state["current_phase"] = "analysis"
    
    async def _run_analysis(self, state: AgentGraphState):
        """Run analysis phase"""
        # Analysis is done in analyzer_node
        state["current_phase"] = "completed"
    
    async def scan(self, scan_request: ScanRequest) -> ScanResult:
        """Execute a penetration test scan"""
        
        # Validate target
        is_valid, message = self.validator.validate_url(scan_request.target_url)
        if not is_valid:
            raise ValueError(f"Invalid target URL: {message}")
        
        # Reset page fingerprinter for new scan
        from .page_fingerprinting import reset_fingerprinter
        reset_fingerprinter()
        
        # Check authorization (reload config to get latest)
        self.auth_manager._load_config()
        
        if not self.auth_manager.is_authorized(scan_request.target_url):
            raise PermissionError(
                f"Target {scan_request.target_url} is not authorized. "
                "Add it to authorized targets first."
            )
        
        # Initialize context manager for this scan
        self.context_manager = ContextManager(max_context_tokens=100000)
        
        # Initialize state
        scan_id = str(uuid.uuid4())
        thread_id = f"scan_{scan_id}"  # Unique thread ID for checkpointing
        
        # Save scan metadata for recovery
        scan_checkpointer = get_checkpointer()
        scan_checkpointer.save_scan_metadata(
            scan_id=scan_id,
            thread_id=thread_id,
            target_url=scan_request.target_url,
            status="running"
        )
        
        initial_state: AgentGraphState = {
            "messages": [],  # Start with empty messages - system prompt goes in template
            "scan_id": scan_id,
            "target_url": scan_request.target_url,
            "mode": scan_request.mode.value,
            "current_phase": "reconnaissance",
            "urls_to_scan": [scan_request.target_url],
            "scanned_urls": [],
            "forms": [],
            "vulnerabilities": [],
            "discovered_endpoints": [],
            "pending_approval": None,
            "context": {},
            "completed_actions": [],  # Track completed actions
            "conversation_history": [],  # Persistent conversation memory
            "recent_actions": []  # Last 5 actions to prevent immediate repetition
        }
        
        # Run the graph with HIGH recursion limit for thorough scanning
        config = {
            "recursion_limit": 250,  # Allow up to 250 cycles for thorough testing
        }
        
        try:
            final_state = await self.graph.ainvoke(initial_state, config=config)
            
            # Update scan status on completion
            scan_checkpointer.update_scan_status(
                scan_id=scan_id,
                status="completed",
                current_phase=final_state.get("current_phase", "completed"),
                urls_scanned=len(final_state.get("scanned_urls", [])),
                vulnerabilities_found=len(final_state.get("vulnerabilities", []))
            )
        except Exception as e:
            # Update scan status on failure
            scan_checkpointer.update_scan_status(
                scan_id=scan_id,
                status="failed"
            )
            raise
        
        # Build scan result
        target = Target(
            url=scan_request.target_url,
            authorized=True,
            scope_patterns=scan_request.scope_patterns,
            excluded_patterns=scan_request.excluded_patterns
        )
        
        # Convert vulnerability dicts back to Vulnerability objects
        vulnerabilities = [
            Vulnerability(**vuln_dict) 
            for vuln_dict in final_state["vulnerabilities"]
        ]
        
        from datetime import datetime
        scan_result = ScanResult(
            scan_id=scan_id,
            target=target,
            mode=scan_request.mode,
            status=ScanStatus.COMPLETED,
            vulnerabilities=vulnerabilities,
            urls_discovered=len(final_state["scanned_urls"]),
            actions_performed=len(final_state["scanned_urls"]),
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow()
        )
        
        return scan_result
    
    def set_approval_callback(self, callback):
        """Set callback function for approval requests"""
        self.approval_callback = callback

