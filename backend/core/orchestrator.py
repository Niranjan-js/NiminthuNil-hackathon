import asyncio
import logging
import datetime
from typing import Dict, Any, List
from core.planner_agent import PlannerAgent

logger = logging.getLogger("niravan.core.orchestrator")

class CyberEventOrchestrator:
    """
    Asyncio-based central event bus and pipeline controller. Matches incoming
    telemetry events, runs autonomous agent cycles, and broadcasts results
    to SSE listeners in real-time.
    """

    def __init__(self):
        self.event_queue = asyncio.Queue()
        self.active_cycles = {}
        self.sse_subscribers = []

    async def enqueue_event(self, event_data: Dict[str, Any]):
        """
        Enqueue a security incident event to be processed by the planner loop.
        """
        incident_id = event_data.get("id")
        logger.info(f"Enqueuing incident event: {incident_id}")
        
        # Add timestamp if missing
        if "timestamp" not in event_data:
            event_data["timestamp"] = datetime.datetime.utcnow().isoformat()
            
        await self.event_queue.put(event_data)

    async def process_next_event(self, db_session_factory):
        """
        Pop the next event from the queue, execute the ReAct cycle, and broadcast updates.
        """
        event_data = await self.event_queue.get()
        incident_id = event_data.get("id")
        
        # Mark as active
        self.active_cycles[incident_id] = {
            "status": "processing",
            "start_time": datetime.datetime.utcnow().isoformat()
        }
        
        # Broadcast initial state to SSE clients
        await self.broadcast_sse({
            "event": "planner_started",
            "incident_id": incident_id,
            "message": f"Planner loop started for incident {incident_id}"
        })
        
        session = db_session_factory()
        try:
            # Instantiate planner
            planner = PlannerAgent(session)
            
            # Execute loop
            result = await planner.run_cycle(event_data)
            
            # Update status
            self.active_cycles[incident_id] = {
                "status": result.get("status"),
                "end_time": datetime.datetime.utcnow().isoformat(),
                "result": result
            }
            
            # Broadcast final results
            await self.broadcast_sse({
                "event": "planner_completed",
                "incident_id": incident_id,
                "status": result.get("status"),
                "result": result
            })
            
        except Exception as e:
            logger.error(f"Error processing event {incident_id}: {e}", exc_info=True)
            self.active_cycles[incident_id] = {
                "status": "failed",
                "error": str(e)
            }
            await self.broadcast_sse({
                "event": "planner_failed",
                "incident_id": incident_id,
                "error": str(e)
            })
        finally:
            session.close()
            self.event_queue.task_done()

    async def broadcast_sse(self, message: Dict[str, Any]):
        """
        Push message to all SSE subscriber queues.
        """
        if not self.sse_subscribers:
            return
            
        logger.info(f"Broadcasting SSE message event: {message.get('event')}")
        
        # Create a list copy to avoid modification issues during iteration
        subscribers = list(self.sse_subscribers)
        for q in subscribers:
            try:
                q.put_nowait(message)
            except Exception as e:
                logger.warning(f"Failed to push message to subscriber queue: {e}")

    def subscribe_sse(self) -> asyncio.Queue:
        """
        Create and register a new SSE client queue.
        """
        q = asyncio.Queue()
        self.sse_subscribers.append(q)
        logger.info(f"New client subscribed to SSE stream. Total: {len(self.sse_subscribers)}")
        return q

    def unsubscribe_sse(self, queue: asyncio.Queue):
        """
        Unregister a closed SSE client queue.
        """
        if queue in self.sse_subscribers:
            self.sse_subscribers.remove(queue)
            logger.info(f"Client unsubscribed from SSE stream. Total: {len(self.sse_subscribers)}")

    def get_status(self) -> Dict[str, Any]:
        """
        Retrieve queue depth and active subscriber metrics.
        """
        return {
            "queue_depth": self.event_queue.qsize(),
            "active_cycles_count": len(self.active_cycles),
            "sse_subscribers_count": len(self.sse_subscribers),
            "active_incident_ids": list(self.active_cycles.keys())
        }

# Module-level singleton
orchestrator = CyberEventOrchestrator()

async def start_background_processor(db_session_factory):
    """
    Run the event consumer loop in the background.
    """
    logger.info("Starting background cyber event orchestrator worker...")
    while True:
        try:
            await orchestrator.process_next_event(db_session_factory)
        except asyncio.CancelledError:
            logger.info("Background processor task cancelled.")
            break
        except Exception as e:
            logger.error(f"Event bus loop encountered error: {e}")
            await asyncio.sleep(2)
