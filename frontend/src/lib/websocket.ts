const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

export type WsMessage =
  | { type: 'log'; level: string; message: string; tool: string }
  | { type: 'progress'; phase: string; percent: number; status: string }
  | { type: 'finding'; finding: any }
  | { type: 'tool_status'; tool: string; status: string }
  | { type: 'ping' };

export class ScanWebSocket {
  private ws: WebSocket | null = null;
  private scanId: string;
  private handlers: Map<string, ((msg: any) => void)[]> = new Map();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private shouldReconnect = true;

  constructor(scanId: string) {
    this.scanId = scanId;
  }

  connect(): void {
    this.ws = new WebSocket(`${WS_BASE}/ws/scans/${this.scanId}`);

    this.ws.onopen = () => {
      console.log(`WebSocket connected for scan ${this.scanId}`);
      this.emit('connected', {});
    };

    this.ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        if (msg.type !== 'ping') {
          this.emit(msg.type, msg);
          this.emit('*', msg);
        }
      } catch (e) {
        console.warn('WebSocket parse error:', e);
      }
    };

    this.ws.onclose = () => {
      if (this.shouldReconnect) {
        this.reconnectTimer = setTimeout(() => this.connect(), 3000);
      }
    };

    this.ws.onerror = (err) => {
      console.error('WebSocket error:', err);
    };
  }

  on(type: string, handler: (msg: any) => void): void {
    if (!this.handlers.has(type)) this.handlers.set(type, []);
    this.handlers.get(type)!.push(handler);
  }

  off(type: string, handler: (msg: any) => void): void {
    const handlers = this.handlers.get(type) || [];
    this.handlers.set(type, handlers.filter(h => h !== handler));
  }

  private emit(type: string, msg: any): void {
    (this.handlers.get(type) || []).forEach(h => h(msg));
  }

  disconnect(): void {
    this.shouldReconnect = false;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.ws?.close();
  }
}
