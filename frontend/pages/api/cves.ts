import type { NextApiRequest, NextApiResponse } from 'next'
import fs from 'fs'
import path from 'path'

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  try {
    const cacheFile = path.join(process.cwd(), 'public', 'cve_cache.json')
    const cveData = JSON.parse(fs.readFileSync(cacheFile, 'utf-8'))
    res.status(200).json(cveData)
  } catch (error) {
    res.status(500).json({ error: 'Failed to load CVE data' })
  }
} 