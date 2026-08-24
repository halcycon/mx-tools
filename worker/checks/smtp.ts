import type { CheckResult, CheckRow, Severity } from './types';

const EHLO_NAME = 'dart.invalid';
const PORT_TIMEOUT_MS = 8000;

type ConnectFn = typeof import('cloudflare:sockets').connect;

export function parseSmtpReply(buffer: string): { code: number; text: string; rest: string } | null {
	const normalized = buffer.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
	const lines = normalized.split('\n');
	let consumed = 0;
	const collected: string[] = [];
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		const isLastChunk = i === lines.length - 1 && !normalized.endsWith('\n');
		if (isLastChunk) break;
		const m = /^(\d{3})([ -])(.*)$/.exec(line);
		if (!m) {
			consumed += line.length + 1;
			continue;
		}
		collected.push(m[3]);
		consumed += line.length + 1;
		if (m[2] === ' ') {
			return { code: Number(m[1]), text: collected.join('\n'), rest: normalized.slice(consumed) };
		}
	}
	return null;
}

function timed(): { start: number; done: () => number } {
	const start = Date.now();
	return { start, done: () => Date.now() - start };
}

function bannerOk(code: number): Severity {
	if (code >= 200 && code < 300) return 'ok';
	if (code >= 400) return 'fail';
	return 'warn';
}

async function raceTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			p,
			new Promise<T>((_, reject) => {
				timer = setTimeout(() => reject(new Error(label)), ms);
			}),
		]);
	} finally {
		if (timer) clearTimeout(timer);
	}
}

type Session = {
	socket: import('cloudflare:sockets').Socket;
	reader: ReadableStreamDefaultReader<Uint8Array>;
	leftover: string;
};

async function readReply(session: Session, ms: number): Promise<{ code: number; text: string }> {
	const dec = new TextDecoder();
	const deadline = Date.now() + ms;
	let buf = session.leftover;
	session.leftover = '';
	while (Date.now() < deadline) {
		const parsed = parseSmtpReply(buf);
		if (parsed) {
			session.leftover = parsed.rest;
			return { code: parsed.code, text: parsed.text };
		}
		const { value, done } = await raceTimeout(
			session.reader.read(),
			Math.max(1, deadline - Date.now()),
			'timeout waiting for SMTP reply',
		);
		if (done) break;
		buf += dec.decode(value, { stream: true });
	}
	throw new Error(buf.trim() ? `incomplete SMTP reply: ${buf.slice(0, 180)}` : 'no SMTP reply');
}

async function writeLine(socket: import('cloudflare:sockets').Socket, line: string): Promise<void> {
	const writer = socket.writable.getWriter();
	try {
		await writer.write(new TextEncoder().encode(line));
	} finally {
		writer.releaseLock();
	}
}

function ehloCaps(text: string): { starttls: boolean; auth: string } {
	const lines = text.split(/\n/).map((s) => s.trim());
	const starttls = lines.some((l) => /^starttls$/i.test(l));
	const authLine = lines.find((l) => /^auth\b/i.test(l));
	return { starttls, auth: authLine ? authLine.replace(/^auth\s+/i, '') : '' };
}

async function probePort(
	connect: ConnectFn,
	host: string,
	port: number,
	mode: 'plain' | 'starttls' | 'tls',
): Promise<CheckRow> {
	const name = `TCP ${port}`;
	if (port === 25) {
		return {
			status: 'unsupported',
			name,
			value: 'Blocked on Cloudflare Workers',
			info: 'Inbound SMTP (25) needs the CLI: mx smtp:host',
		};
	}

	const secure = mode === 'tls' ? 'on' : mode === 'starttls' ? 'starttls' : 'off';
	let socket: import('cloudflare:sockets').Socket | undefined;
	try {
		socket = connect({ hostname: host, port }, { secureTransport: secure });
		await raceTimeout(socket.opened, PORT_TIMEOUT_MS, `timeout connecting to ${host}:${port}`);
		let session: Session = {
			socket,
			reader: socket.readable.getReader(),
			leftover: '',
		};
		const greet = await readReply(session, PORT_TIMEOUT_MS);
		await writeLine(session.socket, `EHLO ${EHLO_NAME}\r\n`);
		let ehlo = await readReply(session, PORT_TIMEOUT_MS);
		let caps = ehloCaps(ehlo.text);

		if (mode === 'starttls') {
			if (!caps.starttls) {
				await writeLine(session.socket, 'QUIT\r\n').catch(() => undefined);
				return {
					status: 'warn',
					name,
					value: `${greet.code} open, no STARTTLS`,
					info: greet.text.split('\n')[0],
				};
			}
			await writeLine(session.socket, 'STARTTLS\r\n');
			const ready = await readReply(session, PORT_TIMEOUT_MS);
			if (ready.code !== 220) {
				return {
					status: 'fail',
					name,
					value: `STARTTLS rejected (${ready.code})`,
					info: ready.text.split('\n')[0],
				};
			}
			session.reader.releaseLock();
			const secureSock = session.socket.startTls({ expectedServerHostname: host });
			await raceTimeout(secureSock.opened, PORT_TIMEOUT_MS, 'timeout during STARTTLS');
			session = { socket: secureSock, reader: secureSock.readable.getReader(), leftover: '' };
			socket = secureSock;
			await writeLine(session.socket, `EHLO ${EHLO_NAME}\r\n`);
			ehlo = await readReply(session, PORT_TIMEOUT_MS);
			caps = ehloCaps(ehlo.text);
		}

		await writeLine(session.socket, 'QUIT\r\n').catch(() => undefined);
		const bits = [
			greet.text.split('\n')[0],
			caps.starttls ? 'STARTTLS' : null,
			caps.auth ? `AUTH ${caps.auth}` : null,
		].filter(Boolean);
		return {
			status: bannerOk(greet.code),
			name,
			value: `${greet.code} ${mode === 'tls' ? 'SMTPS' : mode === 'starttls' ? 'STARTTLS' : 'SMTP'}`,
			info: bits.join(' · '),
		};
	} catch (e) {
		return {
			status: 'fail',
			name,
			value: e instanceof Error ? e.message : String(e),
		};
	} finally {
		try {
			await socket?.close();
		} catch {
			/* ignore */
		}
	}
}

export async function runSmtp(target: string, extra?: string): Promise<CheckResult> {
	const t = timed();
	const host = target.replace(/\.$/, '');
	const requested = extra ? Number(extra) : NaN;
	const ports: Array<{ port: number; mode: 'plain' | 'starttls' | 'tls' }> = Number.isFinite(requested)
		? [{ port: requested, mode: requested === 465 ? 'tls' : requested === 587 ? 'starttls' : requested === 25 ? 'plain' : 'plain' }]
		: [
				{ port: 587, mode: 'starttls' },
				{ port: 465, mode: 'tls' },
				{ port: 25, mode: 'plain' },
			];

	const { connect } = await import('cloudflare:sockets');
	const rows: CheckRow[] = [];
	for (const p of ports) {
		rows.push(await probePort(connect, host, p.port, p.mode));
	}

	const open = rows.filter((r) => r.status === 'ok').length;
	const summary = open
		? `${open} submission port(s) answered`
		: rows.every((r) => r.status === 'unsupported')
			? 'Port 25 blocked on Workers — try 587/465'
			: 'No SMTP banner on 587/465';
	return {
		tool: 'smtp',
		title: 'SMTP Test',
		query: extra ? `${host}:${extra}` : host,
		ok: open > 0,
		summary,
		rows,
		related: [
			{ tool: 'mx', label: `MX ${host}`, query: `mx:${host}` },
			{ tool: 'tcp', label: `TCP ${host}:587`, query: `tcp:${host}:587` },
			{ tool: 'tcp', label: `TCP ${host}:465`, query: `tcp:${host}:465` },
		],
		elapsedMs: t.done(),
	};
}
