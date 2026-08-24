declare module 'cloudflare:sockets' {
	export interface SocketOptions {
		secureTransport?: 'off' | 'on' | 'starttls';
		allowHalfOpen?: boolean;
	}
	export interface SocketAddress {
		hostname: string;
		port: number;
	}
	export interface TlsOptions {
		expectedServerHostname?: string;
	}
	export interface SocketInfo {
		remoteAddress?: string;
		localAddress?: string;
	}
	export interface Socket {
		readable: ReadableStream;
		writable: WritableStream;
		opened: Promise<SocketInfo | void>;
		closed: Promise<void>;
		upgraded?: boolean;
		secureTransport?: 'on' | 'off' | 'starttls';
		close(): Promise<void>;
		startTls(options?: TlsOptions): Socket;
	}
	export function connect(address: SocketAddress | string, options?: SocketOptions): Socket;
}
