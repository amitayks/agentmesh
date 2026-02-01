"""
Local web dashboard for owner observability.
Serves a web interface on localhost for monitoring and control.
"""

import json
import asyncio
import logging
import base64
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from aiohttp import web

from .audit import AuditLog, TranscriptStore, TRANSCRIPTS_DIR
from .config import Policy

logger = logging.getLogger(__name__)

# Default limits
TRANSCRIPT_SEARCH_LIMIT = 100

DASHBOARD_DIR = Path(__file__).parent.parent.parent / "dashboard"


class DashboardServer:
    """
    Local HTTP server for the AgentMesh owner dashboard.
    """

    def __init__(
        self,
        client,  # AgentMeshClient
        host: str = "127.0.0.1",
        port: int = 7777,
    ):
        self.client = client
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.audit = AuditLog()

        # Load owner's signing key for transcript decryption
        signing_key = self._load_signing_key()
        self.transcripts = TranscriptStore(signing_key=signing_key)
        self._has_encryption_key = signing_key is not None

        self._setup_routes()

    def _load_signing_key(self) -> Optional[bytes]:
        """
        Load the owner's signing key from the identity for transcript decryption.

        Returns:
            The signing key bytes, or None if not available
        """
        try:
            # Try to get signing key from client identity
            if hasattr(self.client, 'identity') and self.client.identity:
                if hasattr(self.client.identity, 'signing_key_private'):
                    key = self.client.identity.signing_key_private
                    if key:
                        logger.info("Loaded signing key for transcript decryption")
                        return key

            # Fallback: try to load from keystore file
            keystore_path = Path.home() / ".agentmesh" / "keystore.json"
            if keystore_path.exists():
                import nacl.encoding
                with open(keystore_path, 'r') as f:
                    keystore = json.load(f)
                if 'signing_key' in keystore:
                    key_b64 = keystore['signing_key']
                    key_bytes = base64.b64decode(key_b64)
                    logger.info("Loaded signing key from keystore for transcript decryption")
                    return key_bytes

            logger.warning("No signing key available - transcripts cannot be decrypted")
            return None

        except Exception as e:
            logger.error(f"Failed to load signing key: {e}")
            return None

    def _is_localhost_request(self, request: web.Request) -> bool:
        """
        Verify that a request is coming from localhost.

        Args:
            request: The incoming HTTP request

        Returns:
            True if the request is from localhost
        """
        peername = request.transport.get_extra_info('peername')
        if peername is None:
            return False

        host = peername[0]
        return host in ('127.0.0.1', '::1', 'localhost')

    def _setup_routes(self):
        """Setup HTTP routes."""
        self.app.router.add_get('/', self._serve_dashboard)
        self.app.router.add_get('/api/status', self._api_status)
        self.app.router.add_get('/api/sessions', self._api_sessions)
        self.app.router.add_get('/api/logs', self._api_logs)
        self.app.router.add_get('/api/policy', self._api_get_policy)
        self.app.router.add_post('/api/policy', self._api_set_policy)
        self.app.router.add_post('/api/sessions/{session_id}/kill', self._api_kill_session)
        self.app.router.add_post('/api/breaker/pause', self._api_pause)
        self.app.router.add_post('/api/breaker/resume', self._api_resume)
        self.app.router.add_post('/api/breaker/emergency', self._api_emergency)
        self.app.router.add_post('/api/block/{amid}', self._api_block)
        self.app.router.add_post('/api/unblock/{amid}', self._api_unblock)
        self.app.router.add_post('/api/key-rotation', self._api_key_rotation)
        self.app.router.add_get('/api/transcripts', self._api_transcripts)
        self.app.router.add_get('/api/transcripts/{session_id}', self._api_transcript)
        self.app.router.add_get('/api/transcripts/search', self._api_transcript_search)
        self.app.router.add_get('/api/session-key-export/{session_id}', self._api_session_key_export)

    async def start(self):
        """Start the dashboard server."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()

        logger.info(f"Dashboard running at http://{self.host}:{self.port}")

    async def stop(self):
        """Stop the dashboard server."""
        if self.runner:
            await self.runner.cleanup()
            logger.info("Dashboard stopped")

    async def _serve_dashboard(self, request: web.Request) -> web.Response:
        """Serve the main dashboard HTML."""
        dashboard_file = DASHBOARD_DIR / "index.html"

        if dashboard_file.exists():
            return web.FileResponse(dashboard_file)
        else:
            # Fallback: minimal dashboard
            return web.Response(
                text="""
                <!DOCTYPE html>
                <html>
                <head><title>AgentMesh Dashboard</title></head>
                <body style="font-family: system-ui; padding: 40px; background: #0d1117; color: #c9d1d9;">
                    <h1>AgentMesh Dashboard</h1>
                    <p>Dashboard file not found. Make sure dashboard/index.html exists.</p>
                    <p>API endpoints available at /api/*</p>
                </body>
                </html>
                """,
                content_type='text/html'
            )

    async def _api_status(self, request: web.Request) -> web.Response:
        """Get current status."""
        status = self.client.get_status()

        # Get recent logs
        logs = self.audit.get_recent_events(limit=50)
        log_data = [
            {'ts': e.timestamp.isoformat(), 'event': e.event_type, 'data': e.data}
            for e in logs
        ]

        # Get session info
        sessions = [
            {
                'id': s.id,
                'peer': s.initiator_amid if s.receiver_amid == self.client.amid else s.receiver_amid,
                'intent': s.intent.category if s.intent else None,
                'started': s.created_at.isoformat(),
                'messages': s.messages_sent + s.messages_received,
            }
            for s in self.client.session_manager.sessions.values()
        ]

        return web.json_response({
            **status,
            'sessions': sessions,
            'logs': log_data,
            'policy': self.client.policy.to_dict(),
            'reputation': 0.5,  # TODO: Fetch from registry
            'messagesT': sum(s.messages_sent + s.messages_received for s in self.client.session_manager.sessions.values()),
        })

    async def _api_sessions(self, request: web.Request) -> web.Response:
        """Get active sessions."""
        sessions = [
            {
                'id': s.id,
                'initiator': s.initiator_amid,
                'receiver': s.receiver_amid,
                'type': s.session_type.value,
                'state': s.state.value,
                'created_at': s.created_at.isoformat(),
                'expires_at': s.expires_at.isoformat(),
                'messages_sent': s.messages_sent,
                'messages_received': s.messages_received,
            }
            for s in self.client.session_manager.sessions.values()
        ]

        return web.json_response({'sessions': sessions})

    async def _api_logs(self, request: web.Request) -> web.Response:
        """Get audit logs."""
        limit = int(request.query.get('limit', 100))
        event_type = request.query.get('type')

        events = self.audit.get_recent_events(limit=limit, event_type=event_type)

        return web.json_response({
            'logs': [
                {'ts': e.timestamp.isoformat(), 'event': e.event_type, 'data': e.data}
                for e in events
            ]
        })

    async def _api_get_policy(self, request: web.Request) -> web.Response:
        """Get current policy."""
        return web.json_response(self.client.policy.to_dict())

    async def _api_set_policy(self, request: web.Request) -> web.Response:
        """Update policy."""
        try:
            data = await request.json()

            # Update policy
            new_policy = Policy.from_dict(data)
            self.client.policy = new_policy

            # Save to disk
            policy_path = Path.home() / ".agentmesh" / "policy.json"
            new_policy.save(policy_path)

            return web.json_response({'success': True})
        except Exception as e:
            return web.json_response({'error': str(e)}, status=400)

    async def _api_kill_session(self, request: web.Request) -> web.Response:
        """Kill a specific session."""
        session_id = request.match_info['session_id']

        if self.client.session_manager.close_session(session_id):
            self.audit.log_event("session_killed", {'session_id': session_id})
            return web.json_response({'success': True})
        else:
            return web.json_response({'error': 'Session not found'}, status=404)

    async def _api_pause(self, request: web.Request) -> web.Response:
        """
        Pause new connections - reject ALL new KNOCKs.
        Sets a flag that causes all incoming KNOCKs to be rejected.
        """
        # Set the paused flag on the client
        self.client._paused_for_new = True

        # Also set strict mode with empty allowlist as fallback
        self.client.policy.strict_mode = True
        old_allowlist = self.client.policy.allowlist.copy()
        self.client.policy.allowlist = []

        self.audit.log_event("breaker_pause", {
            'previous_allowlist_size': len(old_allowlist),
        })
        return web.json_response({
            'success': True,
            'message': 'New connections paused - all incoming KNOCKs will be rejected',
        })

    async def _api_resume(self, request: web.Request) -> web.Response:
        """Resume connections."""
        self.client._paused_for_new = False
        self.client.policy.strict_mode = False

        self.audit.log_event("breaker_resume", {})
        return web.json_response({'success': True, 'message': 'Connections resumed'})

    async def _api_emergency(self, request: web.Request) -> web.Response:
        """
        Emergency stop - disconnect from network completely.

        NOTE: This only stops network activity. It cannot halt the entire
        agent framework (e.g., the LLM inference loop). For full framework
        halt, the owner must terminate the process externally.
        """
        # Pause new connections first
        self.client._paused_for_new = True

        # Close all active sessions
        sessions_closed = 0
        for session_id in list(self.client.session_manager.sessions.keys()):
            self.client.session_manager.close_session(session_id)
            sessions_closed += 1

        # Disconnect from relay
        await self.client.disconnect()

        self.audit.log_event("emergency_stop", {
            'sessions_closed': sessions_closed,
            'note': 'Network disconnected. Process must be killed externally for full halt.',
        })
        return web.json_response({
            'success': True,
            'message': 'Emergency stop activated - network disconnected',
            'sessions_closed': sessions_closed,
            'warning': 'For full framework halt, terminate the process externally',
        })

    async def _api_block(self, request: web.Request) -> web.Response:
        """
        Block an AMID - add to blocklist AND kill any active sessions with them.
        """
        amid = request.match_info['amid']

        # Add to blocklist if not already
        if amid not in self.client.policy.blocklist:
            self.client.policy.blocklist.append(amid)

        # Kill any active sessions with this AMID
        sessions_killed = 0
        for session_id, session in list(self.client.session_manager.sessions.items()):
            if session.initiator_amid == amid or session.receiver_amid == amid:
                self.client.session_manager.close_session(session_id)
                sessions_killed += 1

        # Invalidate any cached sessions with this peer
        cache_invalidated = 0
        if hasattr(self.client, '_session_cache'):
            cache_invalidated = self.client._session_cache.invalidate(amid)

        # Save updated policy
        policy_path = Path.home() / ".agentmesh" / "policy.json"
        self.client.policy.save(policy_path)

        self.audit.log_event("amid_blocked", {
            'amid': amid,
            'sessions_killed': sessions_killed,
            'cache_invalidated': cache_invalidated,
        })

        return web.json_response({
            'success': True,
            'message': f'Blocked {amid}',
            'sessions_killed': sessions_killed,
            'cache_invalidated': cache_invalidated,
        })

    async def _api_unblock(self, request: web.Request) -> web.Response:
        """Unblock an AMID - remove from blocklist."""
        amid = request.match_info['amid']

        if amid in self.client.policy.blocklist:
            self.client.policy.blocklist.remove(amid)

            # Save updated policy
            policy_path = Path.home() / ".agentmesh" / "policy.json"
            self.client.policy.save(policy_path)

            self.audit.log_event("amid_unblocked", {'amid': amid})
            return web.json_response({'success': True, 'message': f'Unblocked {amid}'})
        else:
            return web.json_response({'success': False, 'message': 'AMID not in blocklist'})

    async def _api_key_rotation(self, request: web.Request) -> web.Response:
        """
        Trigger key rotation from dashboard.

        This generates new signing and exchange keys, updates the registry,
        and invalidates all cached sessions.
        """
        try:
            # Generate new keys
            old_amid = self.client.identity.amid
            self.client.identity.rotate_keys()
            new_amid = self.client.identity.amid

            # Clear session cache (old keys are no longer valid)
            if hasattr(self.client, '_session_cache'):
                self.client._session_cache.invalidate_all()

            # Notify the client
            self.client.on_key_rotation()

            # Re-register with new keys
            await self.client.registry.register(
                self.client.identity,
                capabilities=self.client.config.capabilities,
            )

            self.audit.log_event("key_rotation_triggered", {
                'old_amid': old_amid,
                'new_amid': new_amid,
            })

            return web.json_response({
                'success': True,
                'message': 'Key rotation completed',
                'old_amid': old_amid,
                'new_amid': new_amid,
            })
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            self.audit.log_event("key_rotation_failed", {'error': str(e)})
            return web.json_response({
                'success': False,
                'error': str(e),
            }, status=500)

    async def _api_transcripts(self, request: web.Request) -> web.Response:
        """
        List transcripts with metadata including encrypted/decryptable status.
        """
        peer = request.query.get('peer')
        limit = int(request.query.get('limit', 50))

        # List transcripts from the store
        transcripts = self.transcripts.list_transcripts(peer_amid=peer, limit=limit)

        # Add decryptable field based on encryption key availability
        for t in transcripts:
            t['decryptable'] = self._has_encryption_key if t.get('encrypted', False) else True

        return web.json_response({
            'transcripts': transcripts,
            'has_encryption_key': self._has_encryption_key,
        })

    async def _api_transcript(self, request: web.Request) -> web.Response:
        """
        Get a specific transcript with automatic decryption.

        Returns 403 if transcript is encrypted but encryption key is not available.
        """
        session_id = request.match_info['session_id']

        # Check if encrypted transcript exists but we can't decrypt
        enc_path = TRANSCRIPTS_DIR / f"{session_id}.enc"
        if enc_path.exists() and not self._has_encryption_key:
            return web.json_response({
                'error': 'Encryption key not available',
                'message': 'Cannot decrypt transcript without owner signing key',
                'session_id': session_id,
                'encrypted': True,
            }, status=403)

        transcript = self.transcripts.get_transcript(session_id)
        if transcript:
            # Add metadata
            transcript['encrypted'] = enc_path.exists()
            transcript['decrypted'] = True  # Successfully decrypted
            return web.json_response(transcript)
        else:
            return web.json_response({'error': 'Transcript not found'}, status=404)

    async def _api_transcript_search(self, request: web.Request) -> web.Response:
        """
        Search transcripts with decryption.

        Query params:
            - q: Search query (searches in message content)
            - peer: Filter by peer AMID
            - limit: Max results (default 100, max 100)
        """
        query = request.query.get('q', '').lower()
        peer = request.query.get('peer')
        limit = min(int(request.query.get('limit', TRANSCRIPT_SEARCH_LIMIT)), TRANSCRIPT_SEARCH_LIMIT)

        if not query:
            return web.json_response({
                'error': 'Search query required',
                'message': 'Provide a "q" query parameter',
            }, status=400)

        # Get recent transcripts (limit to 100 most recent for performance)
        all_transcripts = self.transcripts.list_transcripts(peer_amid=peer, limit=TRANSCRIPT_SEARCH_LIMIT)
        results: List[Dict[str, Any]] = []

        for t_meta in all_transcripts:
            if len(results) >= limit:
                break

            session_id = t_meta['session_id']

            # Skip encrypted transcripts if we can't decrypt
            if t_meta.get('encrypted', False) and not self._has_encryption_key:
                continue

            # Load full transcript for search
            transcript = self.transcripts.get_transcript(session_id)
            if not transcript:
                continue

            # Search in messages
            messages = transcript.get('messages', [])
            matches = []
            for i, msg in enumerate(messages):
                content = str(msg.get('content', '')).lower()
                if query in content:
                    matches.append({
                        'index': i,
                        'snippet': content[:200],  # Preview snippet
                    })

            if matches:
                results.append({
                    'session_id': session_id,
                    'initiator': transcript.get('initiator'),
                    'receiver': transcript.get('receiver'),
                    'created_at': transcript.get('created_at'),
                    'match_count': len(matches),
                    'matches': matches[:5],  # Limit matches per transcript
                    'encrypted': t_meta.get('encrypted', False),
                })

        return web.json_response({
            'query': query,
            'results': results,
            'total_results': len(results),
            'limit': limit,
            'has_encryption_key': self._has_encryption_key,
        })

    async def _api_session_key_export(self, request: web.Request) -> web.Response:
        """
        Export base64-encoded session-specific decryption key.

        This allows sharing a single transcript without exposing the master key.
        Only accessible from localhost for security.
        """
        session_id = request.match_info['session_id']

        # Verify localhost-only access
        if not self._is_localhost_request(request):
            logger.warning(f"Rejected session key export from non-localhost: {request.remote}")
            return web.json_response({
                'error': 'Forbidden',
                'message': 'Session key export is only accessible from localhost',
            }, status=403)

        # Check if encryption key is available
        if not self._has_encryption_key:
            return web.json_response({
                'error': 'Encryption key not available',
                'message': 'Cannot export session key without owner signing key',
            }, status=403)

        # Check if transcript exists
        enc_path = TRANSCRIPTS_DIR / f"{session_id}.enc"
        json_path = TRANSCRIPTS_DIR / f"{session_id}.json"
        if not enc_path.exists() and not json_path.exists():
            return web.json_response({
                'error': 'Transcript not found',
                'session_id': session_id,
            }, status=404)

        # Export session-specific key
        session_key_b64 = self.transcripts.export_session_key(session_id)
        if session_key_b64:
            self.audit.log_event("session_key_exported", {
                'session_id': session_id,
            })
            return web.json_response({
                'session_id': session_id,
                'session_key': session_key_b64,
                'format': 'base64',
                'warning': 'Keep this key secure - it can decrypt this transcript',
            })
        else:
            return web.json_response({
                'error': 'Failed to export session key',
            }, status=500)


async def run_dashboard(client, port: int = 7777):
    """Run the dashboard server."""
    server = DashboardServer(client, port=port)
    await server.start()

    # Keep running
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        await server.stop()


def open_dashboard_browser(port: int = 7777, host: str = "127.0.0.1") -> bool:
    """
    Open the dashboard in the default web browser.

    Args:
        port: Dashboard port (default: 7777)
        host: Dashboard host (default: localhost)

    Returns:
        True if browser was opened successfully, False otherwise
    """
    import webbrowser

    url = f"http://{host}:{port}"

    try:
        # Try to open the browser
        result = webbrowser.open(url)

        if result:
            logger.info(f"Opened dashboard in browser: {url}")
        else:
            logger.warning(f"Could not open browser. Dashboard available at: {url}")

        return result

    except Exception as e:
        logger.warning(f"Failed to open browser: {e}. Dashboard available at: {url}")
        return False


async def start_dashboard_with_browser(
    client,
    port: int = 7777,
    open_browser: bool = True,
) -> DashboardServer:
    """
    Start the dashboard server and optionally open browser.

    Args:
        client: AgentMeshClient instance
        port: Dashboard port
        open_browser: Whether to open browser automatically

    Returns:
        The started DashboardServer instance
    """
    server = DashboardServer(client, port=port)
    await server.start()

    if open_browser:
        # Slight delay to ensure server is ready
        await asyncio.sleep(0.5)
        open_dashboard_browser(port=port)

    return server
