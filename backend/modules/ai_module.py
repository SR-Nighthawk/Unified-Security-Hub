import time
import json
import os
import requests
from flask import Blueprint, request, jsonify, Response, stream_with_context
from backend.core.config import CHATS_DIR, REPORTS_DIR
from backend.core.helpers import get_report_data
from dotenv import load_dotenv
from google import genai

from flask_login import login_required, current_user

load_dotenv()

ai_bp = Blueprint('ai', __name__)

# API Keys
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Initialize Gemini client
gemini_client = None
if GEMINI_API_KEY:
    try:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as e:
        print(f"[AI] Gemini client init failed: {e}")

SYSTEM_PROMPT = """You are 'Cyber Sentinel AI', an advanced cybersecurity expert assistant integrated into SecHub — a Unified Security Operations platform.

Your capabilities:
- Analyze vulnerability scan results (network scans, web application scans)
- Explain CVEs, MITRE ATT&CK techniques, and threat actor TTPs
- Provide remediation guidance and hardening recommendations
- Assist with dark web intelligence analysis
- Generate executive security reports and risk assessments

Guidelines:
- Be concise and technically precise
- Use Markdown formatting for better readability
- Prioritize critical findings first
- Reference specific CVE IDs, MITRE IDs when applicable
- Always suggest actionable remediation steps"""


@ai_bp.route("/api/chat/sessions", methods=["GET"])
@login_required
def get_chat_sessions():
    sessions = []
    for file in CHATS_DIR.glob("*.json"):
        try:
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("owner_id") == current_user.id:
                    sessions.append({"id": file.stem, "title": data.get("title", "Untitled Session"), "updated_at": data.get("updated_at", str(file.stat().st_mtime))})
        except: pass
    sessions.sort(key=lambda x: x["updated_at"], reverse=True)
    return jsonify({"success": True, "sessions": sessions})


@ai_bp.route("/api/chat/sessions/<chat_id>", methods=["GET"])
@login_required
def get_chat_session(chat_id):
    file_path = CHATS_DIR / f"{chat_id}.json"
    if not file_path.exists(): return jsonify({"success": False, "error": "Session not found"}), 404
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if data.get("owner_id") != current_user.id:
                return jsonify({"success": False, "error": "Access denied"}), 403
            return jsonify({"success": True, "data": data})
    except Exception as e: return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/api/chat/sessions/<chat_id>", methods=["DELETE"])
def delete_chat_session(chat_id):
    file_path = CHATS_DIR / f"{chat_id}.json"
    if file_path.exists():
        file_path.unlink()
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "File not found"}), 404


@ai_bp.route("/api/chat/models", methods=["GET"])
def list_models():
    """Return available AI models (NVIDIA + Gemini)."""
    models = []
    if NVIDIA_API_KEY:
        models.append({"name": "qwen3-next-80b",     "provider": "NVIDIA", "size": "80B"})
        models.append({"name": "llama-3.3-70b",       "provider": "NVIDIA", "size": "70B"})
        models.append({"name": "nemotron-70b",         "provider": "NVIDIA", "size": "70B"})
    if GEMINI_API_KEY:
        models.append({"name": "gemini-2.5-flash", "provider": "Google", "size": "Cloud"})
        models.append({"name": "gemini-2.0-flash", "provider": "Google", "size": "Cloud"})
    if not models:
        models.append({"name": "none", "provider": "No API Keys", "size": "N/A"})
    return jsonify({"success": True, "models": models})


@ai_bp.route("/api/chat/upload", methods=["POST"])
def upload_chat_file():
    if 'file' not in request.files: return jsonify({"success": False, "error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"success": False, "error": "No selected file"}), 400
    try:
        content = file.read().decode('utf-8', errors='ignore')
        truncated = content[:10000] + ("\n[Truncated...]" if len(content) > 10000 else "")
        return jsonify({"success": True, "filename": file.filename, "content": truncated})
    except Exception as e: return jsonify({"success": False, "error": str(e)}), 500


def chat_with_nvidia(messages, model_name="qwen/qwen3-next-80b-a3b-thinking"):
    """Stream chat via NVIDIA API."""
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"}
    
    # Convert system prompt
    formatted = [{"role": "system", "content": SYSTEM_PROMPT}]
    for m in messages:
        if m.get("role") != "system":
            formatted.append({"role": m["role"], "content": m["content"]})
    
    payload = {
        "model": model_name,
        "messages": formatted,
        "max_tokens": 2048,
        "temperature": 0.7,
        "top_p": 0.9,
        "stream": True
    }
    
    resp = requests.post(url, headers=headers, json=payload, stream=True, timeout=(5, 30))
    if resp.status_code != 200:
        raise Exception(f"NVIDIA API error: {resp.status_code} - {resp.text[:200]}")
    
    for line in resp.iter_lines():
        if line:
            line_str = line.decode('utf-8')
            if line_str.startswith('data: '):
                data_str = line_str[6:].strip()
                if data_str == '[DONE]':
                    break
                try:
                    chunk = json.loads(data_str)
                    content = chunk.get('choices', [{}])[0].get('delta', {}).get('content', '')
                    if content:
                        yield content
                except Exception:
                    continue


def chat_with_gemini(messages, model_name="gemini-2.0-flash"):
    """Chat via Gemini API (non-streaming, yielded as single chunk)."""
    if not gemini_client:
        raise Exception("Gemini client not initialized. Check GEMINI_API_KEY.")
    
    # Build conversation content
    conversation = SYSTEM_PROMPT + "\n\n"
    for m in messages:
        if m.get("role") == "system":
            continue
        role_label = "User" if m["role"] == "user" else "Assistant"
        conversation += f"{role_label}: {m['content']}\n\n"
    conversation += "Assistant: "
    
    response = gemini_client.models.generate_content(model=model_name, contents=conversation)
    yield response.text


@ai_bp.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    """Streaming chat endpoint using NVIDIA (primary) or Gemini (fallback)."""
    try:
        data = request.json
        messages = data.get("messages", [])
        model = data.get("model", "mistral-small")
        chat_id = data.get("chat_id")
        if not chat_id:
            chat_id = f"chat_{int(time.time())}"

        # Context window: keep last 12 messages
        history = [m for m in messages if m.get("role") != "system"]
        if len(history) > 12:
            history = history[-12:]

        def generate():
            full_response = ""
            try:
                # Choose provider based on model
                if "gemini" in model.lower():
                    gen = chat_with_gemini(history, model_name=model)
                elif NVIDIA_API_KEY:
                    nvidia_models = {
                        "qwen3-next-80b":  "qwen/qwen3-next-80b-a3b-thinking",
                        "llama-3.3-70b":   "meta/llama-3.3-70b-instruct",
                        "nemotron-70b":    "nvidia/llama-3.1-nemotron-70b-instruct",
                    }
                    nvidia_model = nvidia_models.get(model, "qwen/qwen3-next-80b-a3b-thinking")
                    gen = chat_with_nvidia(history, model_name=nvidia_model)
                elif GEMINI_API_KEY:
                    gen = chat_with_gemini(history, model_name="gemini-2.5-flash")
                else:
                    yield f"data: {json.dumps({'error': 'No AI API keys configured. Set NVIDIA_API_KEY or GEMINI_API_KEY in .env'})}\n\n"
                    return

                for content in gen:
                    full_response += content
                    yield f"data: {json.dumps({'content': content, 'chat_id': chat_id})}\n\n"

                # Save session
                history.append({"role": "assistant", "content": full_response})
                title = data.get("title") or (next((m["content"] for m in history if m["role"] == "user"), "New Investigation")[:50])
                session_data = {"owner_id": current_user.id, "title": title, "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + history, "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
                with open(CHATS_DIR / f"{chat_id}.json", "w", encoding="utf-8") as f:
                    json.dump(session_data, f, indent=2)

            except Exception as e:
                error_msg = str(e)
                print(f"[AI Chat Error] {error_msg}")
                # Try fallback
                if "nvidia" in model.lower() or "mistral" in model.lower():
                    if GEMINI_API_KEY:
                        try:
                            yield f"data: {json.dumps({'content': '\\n\\n*[Switching to Gemini fallback...]*\\n\\n', 'chat_id': chat_id})}\n\n"
                            full_response += "\n\n*[Switching to Gemini fallback...]*\n\n"
                            for content in chat_with_gemini(history):
                                full_response += content
                                yield f"data: {json.dumps({'content': content, 'chat_id': chat_id})}\n\n"
                            # Save
                            history.append({"role": "assistant", "content": full_response})
                            title = data.get("title") or "Investigation"
                            session_data = {"owner_id": current_user.id, "title": title, "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + history, "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
                            with open(CHATS_DIR / f"{chat_id}.json", "w", encoding="utf-8") as f:
                                json.dump(session_data, f, indent=2)
                            return
                        except Exception as e2:
                            yield f"data: {json.dumps({'error': f'All AI providers failed. NVIDIA: {error_msg[:80]}. Gemini: {str(e2)[:80]}'})}\n\n"
                            return
                yield f"data: {json.dumps({'error': f'AI Error: {error_msg[:150]}'})}\n\n"

        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@ai_bp.route("/api/ai/summary", methods=["POST"])
@login_required
def api_ai_summary():
    """Generate AI summary for a scan report using NVIDIA or Gemini."""
    payload = request.get_json(silent=True) or {}
    report_id, tool_type = payload.get("report_id"), payload.get("tool")
    report = get_report_data(report_id)
    if not report:
        return jsonify({"success": False, "error": "Report not found."}), 404
    
    try:
        data_str = json.dumps({k: v for k, v in report["data"].items() if k not in ["logs", "ai_summary"]})[:8000]
        prompt = f"Summarize this {tool_type} security scan. Focus on critical findings, risk assessment, and recommended actions:\n\n{data_str}\n\nProvide a concise executive summary in Markdown format."

        summary_text = None

        # Try NVIDIA first
        if NVIDIA_API_KEY:
            try:
                url = "https://integrate.api.nvidia.com/v1/chat/completions"
                headers = {"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"}
                resp = requests.post(url, headers=headers, json={
                    "model": "qwen/qwen3-next-80b-a3b-thinking",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1024, "temperature": 0.3
                }, timeout=(5, 60))
                if resp.status_code == 200:
                    summary_text = resp.json()['choices'][0]['message']['content']
            except Exception as e:
                print(f"[AI Summary] NVIDIA failed: {e}")

        # Fallback to Gemini
        if not summary_text and gemini_client:
            try:
                ai_resp = gemini_client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
                summary_text = ai_resp.text
            except Exception as e:
                print(f"[AI Summary] Gemini failed: {e}")

        if not summary_text:
            return jsonify({"success": False, "error": "All AI providers failed."}), 500

        report["data"]["ai_summary"] = summary_text
        with open(REPORTS_DIR / f"{report_id}.json", "w", encoding="utf-8") as f:
            json.dump(report, f)
        return jsonify({"success": True, "data": {"summary": summary_text}})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
