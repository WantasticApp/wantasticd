/**
 * Format a byte count using binary (IEC) units — GiB, MiB, KiB, B.
 * Matches the Go server's formatBytes which uses 1<<30 / 1<<20 / 1<<10.
 */
export function formatBytes(b: number): string {
  const GiB = 1 << 30
  const MiB = 1 << 20
  const KiB = 1 << 10
  if (b >= GiB) return (b / GiB).toFixed(2) + ' GiB'
  if (b >= MiB) return (b / MiB).toFixed(2) + ' MiB'
  if (b >= KiB) return (b / KiB).toFixed(1) + ' KiB'
  return b + ' B'
}
