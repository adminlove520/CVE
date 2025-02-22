import { useState, useEffect } from 'react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

interface Reference {
  url: string;
  type: 'poc' | 'reference';
}

interface CVE {
  id: string;
  publishedDate: string;
  severity: string;
  fixSuggestion: string;
  references: Reference[];
}

interface CVEResponse {
  metadata: {
    total_count: number;
    last_updated: string;
    severity_distribution: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      none: number;
    };
  };
  cves: CVE[];
}

export default function Home() {
  const [cves, setCves] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/cves')
      .then((res) => res.json())
      .then((data: CVEResponse) => {
        setCves(data.cves || []);
        setLoading(false);
      })
      .catch((error) => {
        console.error('Error fetching CVEs:', error);
        setLoading(false);
      });
  }, []);

  return (
    <div className="container mx-auto py-8">
      <h1 className="text-2xl font-bold mb-4">CVE漏洞预警</h1>
      {loading ? (
        <p>加载中...</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>CVE ID</TableHead>
              <TableHead>发布日期</TableHead>
              <TableHead>严重性</TableHead>
              <TableHead>修复建议</TableHead>
              <TableHead>相关链接</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {cves.map((cve: CVE) => (
              <TableRow key={cve.id}>
                <TableCell>{cve.id}</TableCell>
                <TableCell>{new Date(cve.publishedDate).toLocaleDateString()}</TableCell>
                <TableCell>{cve.severity}</TableCell>
                <TableCell>{cve.fixSuggestion}</TableCell>
                <TableCell>
                  {cve.references.map((ref: Reference, index: number) => (
                    <a
                      key={index}
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-500 hover:underline block"
                    >
                      {ref.type === 'poc' ? 'PoC' : 'Reference'}
                    </a>
                  ))}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
} 