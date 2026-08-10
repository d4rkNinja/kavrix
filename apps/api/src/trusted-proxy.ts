import { isIP } from 'node:net';

export function isExplicitIpOrCidr(value: string): boolean {
  if (isIP(value) !== 0) return true;
  const [address, prefix, extra] = value.split('/');
  const family = address === undefined ? 0 : isIP(address);
  if (family === 0 || prefix === undefined || extra !== undefined) return false;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(prefix)) return false;
  const bits = Number(prefix);
  const maximum = family === 4 ? 32 : 128;
  return Number.isInteger(bits) && bits >= 1 && bits <= maximum;
}
