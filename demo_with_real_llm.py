"""
VibeGuard + Real LLM Demo
=========================

This demo shows VibeGuard protecting a REAL Claude API call.
It requires an Anthropic API key to run.

Usage:
    export ANTHROPIC_API_KEY="your-key-here"
    python demo_with_real_llm.py
"""

import os
import sys
sys.path.insert(0, '/home/claude/vibeguard/src')

from vibeguard import Guard


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║   🛡️  VibeGuard + Real LLM Demo                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Check for API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    
    if not api_key:
        print("⚠️  No ANTHROPIC_API_KEY found. Running in simulation mode.")
        print("   To use real Claude API, set: export ANTHROPIC_API_KEY='your-key'")
        use_real_api = False
    else:
        print("✅ Anthropic API key found!")
        use_real_api = True
        
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            print("⚠️  anthropic package not installed. Run: pip install anthropic")
            use_real_api = False
    
    # Create VibeGuard
    guard = Guard(
        check_prompt_injection=True,
        check_pii=True,
        check_secrets=True,
        redact_pii=True,
        block_on_injection=True,
    )
    
    print("\n" + "="*70)
    print("Type messages to chat with Claude (protected by VibeGuard)")
    print("Try injection attacks, PII, etc. to see VibeGuard in action!")
    print("Type 'quit' to exit")
    print("="*70)
    
    conversation_history = []
    
    while True:
        try:
            user_input = input("\n💬 You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n👋 Bye!")
            break
        
        if not user_input:
            continue
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("👋 Bye!")
            break
        
        # === STEP 1: VibeGuard checks the input ===
        print("\n🔍 VibeGuard scanning input...")
        input_result = guard.check_input(user_input)
        
        if input_result.blocked:
            print(f"🚫 BLOCKED: {input_result.reason}")
            for issue in input_result.issues:
                conf = issue.metadata.get('confidence', '')
                conf_str = f" ({conf:.0%})" if isinstance(conf, float) else ""
                print(f"   ⚠️  {issue.detail}{conf_str}")
            print("\n🤖 Claude never sees this message!")
            continue
        
        # Show if PII was redacted
        if input_result.sanitized_text != user_input:
            print(f"🔒 PII Redacted: \"{input_result.sanitized_text}\"")
        else:
            print("✅ Input clean")
        
        # === STEP 2: Send to LLM (real or simulated) ===
        if use_real_api:
            try:
                print("📤 Sending to Claude...")
                conversation_history.append({
                    "role": "user",
                    "content": input_result.sanitized_text  # Send SANITIZED text
                })
                
                response = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=500,
                    system="You are a helpful assistant. Be concise.",
                    messages=conversation_history
                )
                
                llm_response = response.content[0].text
                conversation_history.append({
                    "role": "assistant", 
                    "content": llm_response
                })
                
            except Exception as e:
                print(f"❌ API Error: {e}")
                llm_response = f"[Error calling API: {e}]"
        else:
            # Simulated response
            llm_response = f"[Simulated] I received: '{input_result.sanitized_text[:50]}...'"
        
        # === STEP 3: VibeGuard checks the output ===
        print("🔍 VibeGuard scanning output...")
        output_result = guard.check_output(llm_response)
        
        if output_result.blocked:
            print(f"🚫 Response blocked: {output_result.reason}")
            print("\n🤖 Claude: [Response hidden for safety]")
        else:
            if output_result.sanitized_text != llm_response:
                print("🔒 Response sanitized (PII removed)")
            print(f"\n🤖 Claude: {output_result.sanitized_text}")


if __name__ == "__main__":
    main()
