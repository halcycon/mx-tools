declare module 'cloudflare:sockets' {
	export interface SocketOptions {
		secureTransport?: 'off' | 'on' | 'starttls';
		allowHalfOpen?: boolean;
	}
	export interface SocketAddress {
		hostname: string;
		port: number;
	}
	export interface Socket {
		readable: ReadableStream;
		writable: WritableStream;
		opened: Promise<void>;
		closed: Promise<void>;
		close(): Promise<void>;
	}
	export function connect(address: SocketAddress | string, options?: SocketOptions): Socket;
}
