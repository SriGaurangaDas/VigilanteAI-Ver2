
interface OsintReportProps {
  data: {
    whois?: any;
    ssl?: any;
    // Add other OSINT data types here as we implement them
  };
}

const ReportSection: React.FC<{ title: string; data: any }> = ({ title, data }) => {
  if (!data || data.error) {
    return (
      <div className="mb-4">
        <h4 className="text-lg font-semibold text-gray-300">{title}</h4>
        <p className="text-gray-500">{data?.error || 'No data available.'}</p>
      </div>
    );
  }

  return (
    <div className="mb-4">
      <h4 className="text-lg font-semibold text-gray-300">{title}</h4>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2 mt-2 text-sm">
        {Object.entries(data).map(([key, value]) => (
          <div key={key}>
            <span className="font-medium text-gray-400">{key}: </span>
            <span className="text-gray-200">{String(value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default function OsintReport({ data }: OsintReportProps) {
  return (
    <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-4">OSINT Report</h2>

      {data.whois && <ReportSection title="Whois Information" data={data.whois} />}
      {data.ssl && <ReportSection title="SSL/TLS Certificate" data={data.ssl} />}

      {/* Placeholders for other reports will go here */}
    </div>
  );
}
