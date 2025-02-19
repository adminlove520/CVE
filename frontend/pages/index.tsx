import { useState, useEffect } from 'react'
import { DataGrid } from '@mui/x-data-grid'

interface CVE {
  id: string;
  publishedDate: string;
  severity: string;
  remediation: string;
  references: string[];
}

export default function Home() {
  const [cves, setCves] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(true);

  const columns = [
    { field: 'id', headerName: 'CVE ID', width: 150 },
    { field: 'publishedDate', headerName: '发布日期', width: 150 },
    { field: 'severity', headerName: '严重性', width: 120 },
    { 
      field: 'remediation',
      headerName: '修复建议',
      width: 300,
      renderCell: (params: any) => (
        <div style={{ whiteSpace: 'pre-wrap' }}>
          {params.value}
        </div>
      )
    },
    {
      field: 'references',
      headerName: '相关链接',
      width: 200,
      renderCell: (params: any) => (
        <div>
          {params.value.map((link: string, index: number) => (
            <a key={index} href={link} target="_blank" rel="noopener noreferrer">
              {link.includes('poc') ? 'PoC' : 'CVE.org'}
            </a>
          ))}
        </div>
      )
    }
  ];

  useEffect(() => {
    fetchCVEs();
  }, []);

  const fetchCVEs = async () => {
    try {
      const response = await fetch('/api/cves');
      const data = await response.json();
      setCves(data);
    } catch (error) {
      console.error('Error fetching CVEs:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">CVE 漏洞预警系统</h1>
      <div style={{ height: 600, width: '100%' }}>
        <DataGrid
          rows={cves}
          columns={columns}
          loading={loading}
          pagination
          getRowId={(row) => row.id}
        />
      </div>
    </div>
  );
} 