"""
Local web dashboard for owner observability.
Serves a web interface on localhost for monitoring and control.
"""

import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from aiohttp import web

from .audit import AuditLog, TranscriptStore
from .config import Policy

logger = logging.getLogger(__name__)

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
        self.transcripts = TranscriptStore()

        self._setup_routes()

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
        self.app.router.add_get('/api/transcripts', self._api_transcripts)
        self.app.router.add_get('/api/transcripts/{session_id}', self._api_transcript)

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
        """Pause new connections."""
        # Set policy to strict mode with empty allowlist
        self.client.policy.strict_mode = True
        self.client.policy.allowlist = []

        self.audit.log_event("breaker_pause", {})
        return web.json_response({'success': True, 'message': 'New connections paused'})

    async def _api_resume(self, request: web.Request) -> web.Response:
        """Resume connections."""
        self.client.policy.strict_mode = False

        self.audit.log_event("breaker_resume", {})
        return web.json_response({'success': True, 'message': 'Connections resumed'})

    async def _api_emergency(self, request: web.Request) -> web.Response:
        """Emergency stop - disconnect from network."""
        # Close all sessions
        for session_id in list(self.client.session_manager.sessions.keys()):
            self.client.session_manager.close_session(session_id)

        # Disconnect
        await self.client.disconnect()

        self.audit.log_event("emergency_stop", {})
        return web.json_response({'success': True, 'message': 'Emergency stop activated'})

    async def _api_transcripts(self, request: web.Request) -> web.Response:
        """List transcripts."""
        peer = request.query.get('peer')
        limit = int(request.query.get('limit', 50))

        transcripts = self.transcripts.list_transcripts(peer_amid=peer, limit=limit)
        return web.json_response({'transcripts': transcripts})

    async def _api_transcript(self, request: web.Request) -> web.Response:
        """Get a specific transcript."""
        session_id = request.match_info['session_id']

        transcript = self.transcripts.get_transcript(session_id)
        if transcript:
            return web.json_response(transcript)
        else:
            return web.json_response({'error': 'Transcript not found'}, status=404)


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
