import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export type Status = 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'SKIP';
export interface Evidence { schema_version: string; experiment_id: string; evidence_class: 'synthetic'|'observed'; model_tested: boolean; independent_trials: boolean; checks: Array<{name:string;status:Status;detail:string}>; }
export function validateEvidence(x: unknown): string[] {
  const errors: string[] = [];
  if (!x || typeof x !== 'object') return ['root must be an object'];
  const e = x as Partial<Evidence>;
  if (e.schema_version !== '1.0') errors.push('schema_version must equal 1.0');
  if (typeof e.experiment_id !== 'string' || !e.experiment_id.trim()) errors.push('experiment_id required');
  if (!['synthetic','observed'].includes(String(e.evidence_class))) errors.push('invalid evidence_class');
  if (typeof e.model_tested !== 'boolean') errors.push('model_tested must be boolean');
  if (typeof e.independent_trials !== 'boolean') errors.push('independent_trials must be boolean');
  if (!Array.isArray(e.checks)) errors.push('checks must be an array');
  else e.checks.forEach((c,i)=> { if (!c || typeof c.name!=='string' || !['PASS','FAIL','INCONCLUSIVE','SKIP'].includes(c.status) || typeof c.detail!=='string') errors.push(`checks[${i}] invalid`); });
  if (e.evidence_class === 'synthetic' && e.model_tested === true) errors.push('synthetic evidence cannot claim model_tested=true');
  return errors;
}
export function sha256(path: string): string { return createHash('sha256').update(readFileSync(path)).digest('hex'); }
export function summarize(checks: Evidence['checks']) {
  return checks.reduce((a,c)=>{ a[c.status]++; return a; }, {PASS:0,FAIL:0,INCONCLUSIVE:0,SKIP:0});
}
export function wilson95(successes:number, trials:number): {low:number;high:number} {
  if (!Number.isInteger(successes)||!Number.isInteger(trials)||trials<=0||successes<0||successes>trials) throw new Error('invalid binomial counts');
  const z=1.959963984540054, p=successes/trials, d=1+z*z/trials;
  const center=(p+z*z/(2*trials))/d, half=z*Math.sqrt(p*(1-p)/trials+z*z/(4*trials*trials))/d;
  // Preserve exact logical boundaries against floating-point roundoff.
  const low = successes === 0 ? 0 : Math.max(0, center-half);
  const high = successes === trials ? 1 : Math.min(1, center+half);
  return {low, high};
}
export function binomialIntervalAllowed(independentTrials:boolean): void {
  if (!independentTrials) throw new Error('refusing CI: trials are not documented as independent');
}
