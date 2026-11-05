import { DAY } from '../report/config';

export const ZONE = 'Europe/London';
const dateFormatter = new Intl.DateTimeFormat('en-CA', { timeZone: ZONE, year: 'numeric', month: '2-digit', day: '2-digit' });

function dateInLondon(now: number): string {
	const p = dateFormatter.formatToParts(now);
	const get = (name: string) => p.find(p => p.type === name)!.value;
	return `${get('year')}-${get('month')}-${get('day')}`;
}

function midnight(day: string): number {
	const utc = Date.parse(`${day}T00:00:00Z`);
	const hour = Number(new Intl.DateTimeFormat('en-GB', { timeZone: ZONE, hour: '2-digit', hourCycle: 'h23' }).format(utc));
	return utc - hour * 3_600_000;
}

export function previousLondonDay(now: number) {
	const today = dateInLondon(now);
	const day = new Date(Date.parse(`${today}T12:00:00Z`) - DAY).toISOString().slice(0, 10);
	return { day, start: midnight(day), end: midnight(today) };
}

export function currentLondonDay(now: number) {
	const day = dateInLondon(now);
	const tomorrow = new Date(Date.parse(`${day}T12:00:00Z`) + DAY).toISOString().slice(0, 10);
	return { day, start: midnight(day), end: midnight(tomorrow) };
}
