// ============================================================================
// ai-nexus-gateway — src/transport/WebSocketNodeTransport.ts
// Real-time WebSocket Node Transport (`/ws/node` over WS & WSS behind Render TLS)
// ============================================================================

import { Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import {
  computeDeterministicSignature,
  GatewayNodeWsFrame,
  InvocationRecord,
} from '@ai-nexus/protocol';
import { IdentityRegistry } from '../identity/IdentityRegistry.ts';
import { InvocationManager } from '../invocation/InvocationManager.ts';
import { OfflineQueueManager } from '../queue/OfflineQueueManager.ts';
import { GatewayAuditService } from '../audit/AuditService.ts';
import { isOriginAllowed } from '../security/SecurityGuards.ts';

export class WebSocketNodeTransport {
  private wss: WebSocketServer;
  private activeNodeSockets = new Map<string, WebSocket>(); // aiId -> WebSocket

  constructor(
    httpServer: HttpServer,
    wsPath: string,
    allowedOriginsCsv: string,
    private identities: IdentityRegistry,
    private invocations: InvocationManager,
    private offlineQueue: OfflineQueueManager,
    private audit: GatewayAuditService
  ) {
    this.wss = new WebSocketServer({
      server: httpServer,
      path: wsPath,
      verifyClient: (info, done) => {
        const origin = info.origin || info.req.headers.origin;
        if (!isOriginAllowed(origin, allowedOriginsCsv)) {
          done(false, 403, 'Origin not allowed by AI Nexus Gateway CORS policy');
          return;
        }
        done(true);
      },
    });

    this.wss.on('connection', (ws) => {
      let boundAiId: string | null = null;

      ws.on('message', (raw) => {
        try {
          const frame = JSON.parse(raw.toString()) as GatewayNodeWsFrame;

          if (frame.type === 'ping') {
            if (frame.aiId) this.identities.recordHeartbeat(frame.aiId);
            this.sendFrame(ws, { type: 'pong', timestamp: new Date().toISOString() });
            return;
          }

          if (frame.type === 'node.authenticate') {
            const identity = this.identities.get(frame.aiId);
            if (!identity || identity.registrationState === 'REVOKED') {
              this.sendFrame(ws, {
                type: 'node.auth_failed',
                reason: `Identity '${frame.aiId}' is not registered or has been revoked.`,
              });
              ws.close(4001, 'Authentication failed');
              return;
            }

            const expectedSig = computeDeterministicSignature(
              `ws_auth:${frame.aiId}:${frame.nodeId}:${frame.nonce}`,
              identity.keyFingerprint
            );
            if (
              frame.keyFingerprint !== identity.keyFingerprint ||
              frame.signature !== expectedSig
            ) {
              this.sendFrame(ws, {
                type: 'node.auth_failed',
                reason: 'Invalid Ed25519 WebSocket node authentication signature.',
              });
              ws.close(4003, 'Invalid signature');
              return;
            }

            boundAiId = identity.aiId;
            this.activeNodeSockets.set(identity.aiId, ws);
            this.identities.updateStatus(identity.aiId, { online: true });
            this.identities.recordHeartbeat(identity.aiId);

            // Drain any queued offline invocations for this reconnected node
            const { validRecords } = this.offlineQueue.drainEligible(identity.aiId);
            for (const drained of validRecords) {
              drained.queuedOffline = false;
              this.invocations.saveRecord(drained);
            }

            this.audit.record({
              repository: 'ai-nexus-gateway',
              module: 'WebSocketNodeTransport',
              eventType: 'NODE_WS_CONNECTED',
              actorAiId: identity.aiId,
              outcome: 'SUCCESS',
              summary: `Personal AI node ${identity.nodeId} (${identity.handle}) established authenticated WebSocket connection on ${wsPath} (${validRecords.length} queued requests drained).`,
            });

            this.sendFrame(ws, {
              type: 'node.authenticated',
              aiId: identity.aiId,
              nodeId: frame.nodeId,
              timestamp: new Date().toISOString(),
              drainedQueueCount: validRecords.length,
            });

            // Deliver drained offline requests over WebSocket
            for (const rec of validRecords) {
              this.deliverInvocationToNode(identity.aiId, rec);
            }
            return;
          }

          if (frame.type === 'invocation.transition') {
            this.invocations.transition(
              frame.requestId,
              frame.state,
              frame.summary,
              frame.actor
            );
            return;
          }

          if (frame.type === 'invocation.response') {
            this.invocations.completeWithResponse(
              frame.requestId,
              frame.responseEnvelope
            );
            this.audit.record({
              repository: 'ai-nexus-gateway',
              module: 'MessageRouter',
              eventType: 'INVOCATION_RESPONSE_ROUTED',
              actorAiId: frame.responseEnvelope.senderAiId,
              targetAiId: frame.responseEnvelope.recipientAiId,
              correlationId: frame.responseEnvelope.correlationId,
              outcome:
                frame.responseEnvelope.payload.status === 'COMPLETED'
                  ? 'SUCCESS'
                  : 'DENIED',
              summary: `Routed response envelope for ${frame.requestId} from ${frame.responseEnvelope.senderAiId} to ${frame.responseEnvelope.recipientAiId} (${frame.responseEnvelope.payload.status}).`,
            });
            return;
          }
        } catch {
          // Ignore malformed frame
        }
      });

      ws.on('close', () => {
        if (boundAiId && this.activeNodeSockets.get(boundAiId) === ws) {
          this.activeNodeSockets.delete(boundAiId);
          this.identities.updateStatus(boundAiId, { online: false });
        }
      });
    });
  }

  private sendFrame(ws: WebSocket, frame: GatewayNodeWsFrame): boolean {
    if (ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify(frame));
    return true;
  }

  isNodeSocketConnected(aiId: string): boolean {
    const ws = this.activeNodeSockets.get(aiId);
    const identity = this.identities.get(aiId);
    return Boolean(ws && ws.readyState === WebSocket.OPEN && identity?.online);
  }

  getConnectedAiIds(): string[] {
    const list: string[] = [];
    for (const [aiId, ws] of this.activeNodeSockets.entries()) {
      const identity = this.identities.get(aiId);
      if (ws.readyState === WebSocket.OPEN && identity?.online) {
        list.push(aiId);
      }
    }
    return list;
  }

  deliverInvocationToNode(recipientAiId: string, record: InvocationRecord): boolean {
    const ws = this.activeNodeSockets.get(recipientAiId);
    const identity = this.identities.get(recipientAiId);
    if (!ws || ws.readyState !== WebSocket.OPEN || !identity?.online) {
      return false;
    }
    return this.sendFrame(ws, {
      type: 'invocation.deliver',
      requestId: record.requestId,
      envelope: record.envelope,
    });
  }

  drainOfflineQueueForNode(recipientAiId: string): InvocationRecord[] {
    if (!this.isNodeSocketConnected(recipientAiId)) {
      return [];
    }
    const { validRecords } = this.offlineQueue.drainEligible(recipientAiId);
    for (const rec of validRecords) {
      rec.queuedOffline = false;
      this.invocations.saveRecord(rec);
      this.deliverInvocationToNode(recipientAiId, rec);
    }
    return validRecords;
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      for (const [aiId, ws] of this.activeNodeSockets.entries()) {
        try {
          this.identities.updateStatus(aiId, { online: false });
          ws.close(1001, 'Gateway shutting down');
          ws.terminate();
        } catch {
          // ignore
        }
      }
      for (const client of this.wss.clients) {
        try {
          client.close(1001, 'Gateway shutting down');
          client.terminate();
        } catch {
          // ignore
        }
      }
      this.activeNodeSockets.clear();
      this.wss.close(() => resolve());
    });
  }
}
