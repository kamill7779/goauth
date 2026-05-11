export default function StatusBadge({ status, text }: { status: string; text?: string }) {
  const styleMap: Record<string, string> = {
    active: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    disabled: 'bg-gray-100 text-gray-500 border-gray-200',
    inactive: 'bg-gray-100 text-gray-500 border-gray-200',
    pending: 'bg-amber-50 text-amber-700 border-amber-200',
    expired: 'bg-amber-50 text-amber-700 border-amber-200',
    suspended: 'bg-red-50 text-red-700 border-red-200',
    blocked: 'bg-red-50 text-red-700 border-red-200',
    failed: 'bg-red-50 text-red-700 border-red-200',
    success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    trial: 'bg-blue-50 text-blue-700 border-blue-200',
  };
  const labelMap: Record<string, string> = {
    active: '活跃', disabled: '停用', inactive: '停用', pending: '待验证', suspended: '已冻结',
    blocked: '已拦截', failed: '失败', success: '成功', trial: '试用', expired: '已过期',
  };
  const dotMap: Record<string, string> = {
    active: 'bg-emerald-500', success: 'bg-emerald-500',
    pending: 'bg-amber-500', trial: 'bg-amber-500', expired: 'bg-amber-500',
    disabled: 'bg-gray-400', inactive: 'bg-gray-400',
    suspended: 'bg-red-500', blocked: 'bg-red-500', failed: 'bg-red-500',
  };
  const style = styleMap[status] || styleMap.inactive;
  const label = text || labelMap[status] || status;
  const dot = dotMap[status] || 'bg-gray-400';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full border ${style}`}>
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${dot}`} />
      {label}
    </span>
  );
}
