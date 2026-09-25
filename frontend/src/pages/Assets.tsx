import React, { useState, useEffect, useCallback, useMemo, memo, useRef } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  useReactFlow,
  ReactFlowProvider,
} from '@xyflow/react';
import type { Node, Edge } from '@xyflow/react';

import '@xyflow/react/dist/style.css';
import {
  Globe,
  Server,
  Cable,
  Cpu,
  Boxes,
  Search,
  Maximize2,
  Minimize2,
  RefreshCw,
  Shield,
  X,
  ExternalLink,
  Layers,
  Crosshair,
  Copy,
  Check,
} from 'lucide-react';
import { apiFetch } from '../api';
import { PageHeader } from '../components/PageHeader';
import { EmptyState } from '../components/EmptyState';
import { formatDate } from '../components/format';
import { DataTable } from '../components/DataTable';

type AssetType = 'all' | 'domain' | 'ip' | 'port' | 'tech';

const TYPE_ICON: Record<string, React.ReactNode> = {
  domain: <Globe className="w-3.5 h-3.5" aria-hidden="true" />,
  ip: <Server className="w-3.5 h-3.5" aria-hidden="true" />,
  port: <Cable className="w-3.5 h-3.5" aria-hidden="true" />,
  tech: <Cpu className="w-3.5 h-3.5" aria-hidden="true" />,
};

/* ------------------------------------------------------------------------- */
/* Custom Node Components for Attack Surface Topology Graph                  */
/* ------------------------------------------------------------------------- */

const ScopeNode = memo(({ data, selected }: any) => (
  <div
    className={`group relative rounded-2xl border bg-surface-2/95 px-4 py-3 shadow-[var(--shadow-lift)] transition-all duration-300 min-w-[220px] ${
      selected
        ? 'border-accent ring-2 ring-accent/40 shadow-[0_0_24px_rgba(232,255,61,0.25)]'
        : 'border-accent/40 hover:border-accent/80'
    }`}
  >
    <Handle type="source" position={Position.Bottom} className="!w-2 !h-2 !bg-accent !border-2 !border-surface" />
    <div className="flex items-center gap-2.5">
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-accent/40 bg-accent/10 text-accent">
        <Shield className="h-4 w-4" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="eyebrow text-[9px] text-accent">Apex Scope</span>
          <span className="dot dot-ok" />
        </div>
        <p className="font-mono text-[12px] font-semibold tracking-tight text-text truncate max-w-[170px]" title={data.label}>
          {data.label}
        </p>
      </div>
    </div>
    <div className="mt-2.5 flex items-center justify-between border-t border-line/60 pt-2 text-[9.5px] font-mono text-faint">
      <span>{data.assetCount ?? 0} total assets</span>
      <span className="text-accent font-medium">verified scope</span>
    </div>
  </div>
));

const DomainNode = memo(({ data, selected }: any) => (
  <div
    className={`group relative rounded-xl border bg-surface/95 px-3 py-2.5 shadow-sm transition-all duration-300 cursor-pointer min-w-[190px] max-w-[220px] ${
      selected
        ? 'border-accent ring-2 ring-accent/30 bg-surface-2 shadow-[0_0_18px_rgba(232,255,61,0.2)]'
        : 'border-line hover:border-accent/50 hover:bg-surface-2/80'
    }`}
  >
    <Handle type="target" position={Position.Top} className="!w-1.5 !h-1.5 !bg-accent/60 !border-2 !border-surface" />
    <Handle type="source" position={Position.Bottom} className="!w-1.5 !h-1.5 !bg-line-strong !border-2 !border-surface" />
    <div className="flex items-center gap-2">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-lg border border-line bg-surface-2 text-muted group-hover:text-accent transition-colors">
        <Globe className="h-3 w-3" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-[11px] font-medium text-text group-hover:text-accent transition-colors" title={data.label}>
          {data.label}
        </p>
      </div>
    </div>
    <div className="mt-1.5 flex items-center justify-between border-t border-line/40 pt-1 text-[9px] font-mono text-faint">
      <span className="text-muted/70">domain</span>
      {data.ipCount > 0 ? (
        <span className="text-accent/90">{data.ipCount} IP{data.ipCount === 1 ? '' : 's'}</span>
      ) : (
        <span className="text-muted/60">{data.status || 'active'}</span>
      )}
    </div>
  </div>
));

const IpNode = memo(({ data, selected }: any) => (
  <div
    className={`group relative rounded-xl border bg-surface/95 px-2.5 py-1.5 shadow-sm transition-all duration-300 cursor-pointer min-w-[155px] max-w-[175px] ${
      selected
        ? 'border-accent ring-2 ring-accent/30 bg-surface-2 shadow-[0_0_18px_rgba(232,255,61,0.2)]'
        : 'border-line hover:border-line-strong hover:bg-surface-2/80'
    }`}
  >
    <Handle type="target" position={Position.Top} className="!w-1.5 !h-1.5 !bg-line-strong !border-2 !border-surface" />
    <Handle type="source" position={Position.Bottom} className="!w-1.5 !h-1.5 !bg-line-strong !border-2 !border-surface" />
    <div className="flex items-center gap-2">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-lg border border-line bg-surface-2 text-faint group-hover:text-text transition-colors">
        <Server className="h-3 w-3" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-[10.5px] font-medium text-text" title={data.label}>
          {data.label}
        </p>
      </div>
    </div>
    {data.domain && (
      <p className="mt-1 truncate font-mono text-[8.5px] text-faint border-t border-line/40 pt-0.5" title={`Linked to ${data.domain}`}>
        ↳ {data.domain.replace('.www.worldmonitor.app', '')}
      </p>
    )}
  </div>
));

const PortNode = memo(({ data, selected }: any) => (
  <div
    className={`group relative rounded-xl border bg-surface/95 px-3 py-2 shadow-sm transition-all duration-300 cursor-pointer min-w-[170px] max-w-[200px] ${
      selected
        ? 'border-medium ring-2 ring-medium/30 bg-surface-2 shadow-[0_0_18px_rgba(255,214,77,0.2)]'
        : 'border-line hover:border-medium/60 hover:bg-surface-2/80'
    }`}
  >
    <Handle type="target" position={Position.Top} className="!w-1.5 !h-1.5 !bg-medium/60 !border-2 !border-surface" />
    <div className="flex items-center gap-2">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-lg border border-medium/30 bg-medium/10 text-medium">
        <Cable className="h-3 w-3" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-[11px] font-semibold text-text">
          {data.label}
        </p>
      </div>
    </div>
    <div className="mt-1 flex items-center justify-between border-t border-line/40 pt-1 text-[9px] font-mono text-faint">
      <span className="text-medium/90 font-medium">{data.service || 'service'}</span>
      <span className="truncate max-w-[80px]">{data.product || ''}</span>
    </div>
  </div>
));

const TechNode = memo(({ data, selected }: any) => (
  <div
    className={`group relative rounded-xl border bg-surface/95 px-3 py-2 shadow-sm transition-all duration-300 cursor-pointer min-w-[160px] max-w-[190px] ${
      selected
        ? 'border-low ring-2 ring-low/30 bg-surface-2 shadow-[0_0_18px_rgba(143,184,255,0.2)]'
        : 'border-line hover:border-low/60 hover:bg-surface-2/80'
    }`}
  >
    <Handle type="target" position={Position.Top} className="!w-1.5 !h-1.5 !bg-low/60 !border-2 !border-surface" />
    <div className="flex items-center gap-2">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-lg border border-low/30 bg-low/10 text-low">
        <Cpu className="h-3 w-3" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-[11px] font-semibold text-text">
          {data.label}
        </p>
      </div>
    </div>
    <div className="mt-1 flex items-center justify-between border-t border-line/40 pt-1 text-[9px] font-mono text-faint">
      <span>tech</span>
      {data.version && <span className="text-low/90 font-mono">v{data.version}</span>}
    </div>
  </div>
));

const AssetNode = memo(({ data }: any) => (
  <div className="rounded-xl border border-line bg-surface-2 px-3 py-1.5 font-mono text-[11px] text-text shadow-sm">
    <Handle type="target" position={Position.Top} className="!bg-line-strong !w-1.5 !h-1.5" />
    {data.label}
  </div>
));

const nodeTypes = {
  scope: ScopeNode,
  domain: DomainNode,
  ip: IpNode,
  port: PortNode,
  tech: TechNode,
  asset: AssetNode,
} as any;

/* ------------------------------------------------------------------------- */
/* Flow Graph Inner Canvas with zoom, search, inspector, and fit controls     */
/* ------------------------------------------------------------------------- */

interface FlowCanvasProps {
  nodes: Node[];
  edges: Edge[];
  onNodesChange: any;
  onEdgesChange: any;
  onSelectNode: (node: Node | null) => void;
  selectedAsset: any;
  onCloseInspector: () => void;
  filterType: AssetType;
  setFilterType: (f: AssetType) => void;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  isFullscreen: boolean;
  setIsFullscreen: (v: boolean) => void;
  totalAssets: number;
}

const FlowCanvas: React.FC<FlowCanvasProps> = ({
  nodes,
  edges,
  onNodesChange,
  onEdgesChange,
  onSelectNode,
  selectedAsset,
  onCloseInspector,
  filterType,
  setFilterType,
  searchQuery,
  setSearchQuery,
  isFullscreen,
  setIsFullscreen,
  totalAssets,
}) => {
  const { fitView } = useReactFlow();
  const [copied, setCopied] = useState(false);

  const handleFit = useCallback(() => {
    fitView({ padding: 0.22, duration: 400 });
  }, [fitView]);

  useEffect(() => {
    // Re-fit when filter changes or on initial render
    const t = setTimeout(() => {
      handleFit();
    }, 150);
    return () => clearTimeout(t);
  }, [filterType, handleFit]);

  const copyAssetValue = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="relative h-full w-full">
      {/* Top Floating Graph Toolbar */}
      <div className="absolute top-3 inset-x-3 z-10 flex flex-wrap items-center justify-between gap-2 pointer-events-none">
        {/* Left Filter Chips */}
        <div className="flex flex-wrap items-center gap-1.5 rounded-xl border border-line bg-surface/90 p-1.5 shadow-lg backdrop-blur-md pointer-events-auto">
          {(['all', 'domain', 'ip', 'port', 'tech'] as AssetType[]).map((type) => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`rounded-lg px-2.5 py-1 text-[10.5px] font-medium transition-all ${
                filterType === type
                  ? 'bg-accent/15 text-accent border border-accent/40 shadow-sm'
                  : 'text-muted hover:text-text hover:bg-white/[0.04]'
              }`}
            >
              {type === 'all'
                ? 'All Nodes'
                : type === 'domain'
                ? 'Domains'
                : type === 'ip'
                ? 'IPs'
                : type === 'port'
                ? 'Ports'
                : 'Tech'}
            </button>
          ))}
        </div>

        {/* Right Search & Controls */}
        <div className="flex items-center gap-2 pointer-events-auto">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-faint" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search graph..."
              className="w-40 sm:w-48 rounded-xl border border-line bg-surface/90 pl-8 pr-3 py-1.5 text-[11px] text-text placeholder:text-faint focus:border-accent/60 focus:outline-none shadow-lg backdrop-blur-md"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-2 text-faint hover:text-text"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          <button
            onClick={handleFit}
            className="flex h-8 w-8 items-center justify-center rounded-xl border border-line bg-surface/90 text-muted transition-colors hover:border-line-strong hover:bg-white/[0.05] hover:text-text shadow-lg backdrop-blur-md"
            title="Reset view / Fit to screen"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>

          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="flex h-8 w-8 items-center justify-center rounded-xl border border-line bg-surface/90 text-muted transition-colors hover:border-line-strong hover:bg-white/[0.05] hover:text-text shadow-lg backdrop-blur-md"
            title={isFullscreen ? 'Exit Fullscreen' : 'Expand Fullscreen'}
          >
            {isFullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

      {/* Floating Node Inspector HUD */}
      {selectedAsset && (
        <div className="absolute bottom-4 left-4 z-20 w-80 rounded-2xl border border-line bg-surface/95 p-4 shadow-[var(--shadow-float)] backdrop-blur-xl animate-in fade-in slide-in-from-bottom-3 duration-200">
          <div className="flex items-center justify-between gap-2 mb-2.5">
            <span className="chip !py-0.5 !text-[9.5px] uppercase tracking-wider text-accent border-accent/40 bg-accent/10">
              {selectedAsset.type}
            </span>
            <button
              onClick={onCloseInspector}
              className="rounded-full p-1 text-faint hover:bg-white/[0.06] hover:text-text transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          <p className="font-mono text-[12.5px] font-semibold text-text break-all mb-3 leading-snug">
            {selectedAsset.value}
          </p>

          <div className="space-y-1.5 text-[10.5px] border-t border-line/60 pt-2.5">
            {selectedAsset.metadata?.service && (
              <div className="flex items-center justify-between">
                <span className="text-faint">Service:</span>
                <span className="font-mono text-muted">{selectedAsset.metadata.service}</span>
              </div>
            )}
            {selectedAsset.metadata?.product && (
              <div className="flex items-center justify-between">
                <span className="text-faint">Product:</span>
                <span className="font-mono text-muted">{selectedAsset.metadata.product}</span>
              </div>
            )}
            {selectedAsset.metadata?.version && (
              <div className="flex items-center justify-between">
                <span className="text-faint">Version:</span>
                <span className="font-mono text-muted">v{selectedAsset.metadata.version}</span>
              </div>
            )}
            {selectedAsset.metadata?.domain && (
              <div className="flex items-center justify-between">
                <span className="text-faint">Linked domain:</span>
                <span className="font-mono text-accent truncate max-w-[160px]">{selectedAsset.metadata.domain}</span>
              </div>
            )}
            {selectedAsset.created_at && (
              <div className="flex items-center justify-between">
                <span className="text-faint">Discovered:</span>
                <span className="mono-cell text-faint">{formatDate(selectedAsset.created_at)}</span>
              </div>
            )}
          </div>

          <div className="mt-3 flex items-center justify-between gap-2 border-t border-line/60 pt-2.5">
            <button
              onClick={() => copyAssetValue(selectedAsset.value)}
              className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface-2 px-3 py-1 text-[10.5px] text-muted hover:border-line-strong hover:text-text transition-colors"
            >
              {copied ? <Check className="h-3 w-3 text-accent" /> : <Copy className="h-3 w-3" />}
              {copied ? 'Copied' : 'Copy value'}
            </button>
            <span className="text-[10px] text-faint font-mono">ID: #{selectedAsset.id}</span>
          </div>
        </div>
      )}

      {/* Main ReactFlow Component */}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={(_, node) => onSelectNode(node)}
        onPaneClick={() => onSelectNode(null)}
        fitView
        fitViewOptions={{ padding: 0.22 }}
        nodesConnectable={false}
        zoomOnScroll
        minZoom={0.15}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
        colorMode="dark"
      >
        <MiniMap
          pannable
          zoomable
          className="!bg-surface-2/90 !border !border-line !rounded-xl !overflow-hidden !w-44 !h-28 !shadow-2xl backdrop-blur-md"
          nodeColor={(n: any) => {
            if (n.type === 'scope') return '#e8ff3d';
            if (n.type === 'domain') return '#8fb8ff';
            if (n.type === 'ip') return '#70d6a5';
            if (n.type === 'port') return '#ffd64d';
            if (n.type === 'tech') return '#d19eff';
            return '#8f9091';
          }}
          maskColor="rgba(6, 6, 7, 0.75)"
        />
        <Controls
          showInteractive={false}
          className="!bg-surface-2/90 !border !border-line !rounded-xl !overflow-hidden !shadow-xl backdrop-blur-md [&>button]:!bg-surface-2 [&>button]:!border-b [&>button]:!border-line [&>button]:!text-muted hover:[&>button]:!text-text hover:[&>button]:!bg-white/[0.06]"
        />
        <Background variant={BackgroundVariant.Dots} color="#26282d" gap={24} size={1.2} />
      </ReactFlow>
    </div>
  );
};

/* ------------------------------------------------------------------------- */
/* Main Assets Page Component                                                */
/* ------------------------------------------------------------------------- */

export const Assets: React.FC = () => {
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [filterType, setFilterType] = useState<AssetType>('all');
  const [graphSearch, setGraphSearch] = useState('');
  const [tableSearch, setTableSearch] = useState('');
  const [selectedAsset, setSelectedAsset] = useState<any | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const flowRef = useRef<any>(null);

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await apiFetch('/auth/assets');
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : [];
        setAssets(list);
      } else {
        const errData = await res.json().catch(() => null);
        setError(errData?.detail || 'Failed to load assets.');
      }
    } catch {
      setError('Server connection failed.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  // Layout builder that creates an aligned 2D topology
  const buildTopology = useCallback(
    (
      items: any[],
      typeFilter: AssetType,
      search: string,
      activeNodeId: string | null
    ) => {
      const newNodes: Node[] = [];
      const newEdges: Edge[] = [];

      const query = search.trim().toLowerCase();

      const domains = items.filter((a) => a.type === 'domain');
      const ips = items.filter((a) => a.type === 'ip');
      const ports = items.filter((a) => a.type === 'port');
      const techs = items.filter((a) => a.type === 'tech');

      const showRoot = typeFilter === 'all' || typeFilter === 'domain';
      if (showRoot) {
        newNodes.push({
          id: 'root',
          data: {
            label: 'worldmonitor.app',
            assetCount: items.length,
          },
          position: { x: 0, y: 0 },
          type: 'scope',
          selected: activeNodeId === 'root',
        });
      }

      // 1. Domains layout (Up to 5 columns per row)
      const DOMAIN_COLS = 5;
      const DOMAIN_X_GAP = 230;
      const DOMAIN_Y_GAP = 85;
      const showDomains = typeFilter === 'all' || typeFilter === 'domain';
      const visibleDomains = showDomains ? domains : [];

      visibleDomains.forEach((d, i) => {
        const col = i % DOMAIN_COLS;
        const row = Math.floor(i / DOMAIN_COLS);
        const colsInThisRow = Math.min(DOMAIN_COLS, visibleDomains.length - row * DOMAIN_COLS);
        const xOffset = (col - (colsInThisRow - 1) / 2) * DOMAIN_X_GAP;
        const yOffset = (showRoot ? 140 : 0) + row * DOMAIN_Y_GAP;

        const isMatch = !query || d.value.toLowerCase().includes(query);
        const isSelected = activeNodeId === `d-${d.id}`;
        const linkedIpCount = ips.filter((ip) => ip.metadata?.domain === d.value).length;

        newNodes.push({
          id: `d-${d.id}`,
          data: {
            label: d.value,
            asset: d,
            assetType: 'domain',
            ipCount: linkedIpCount,
            status: d.metadata?.status,
          },
          position: { x: xOffset, y: yOffset },
          type: 'domain',
          selected: isSelected,
          style: { opacity: isMatch ? 1 : 0.2 },
        });

        if (showRoot) {
          newEdges.push({
            id: `e-root-d-${d.id}`,
            source: 'root',
            target: `d-${d.id}`,
            type: 'smoothstep',
            animated: isSelected,
            style: {
              stroke: isSelected ? '#e8ff3d' : 'rgba(232, 255, 61, 0.22)',
              strokeWidth: isSelected ? 2 : 1,
              opacity: isMatch ? 1 : 0.1,
            },
          });
        }
      });

      // 2. IPs layout (Up to 7 columns per row)
      const IP_COLS = 7;
      const IP_X_GAP = 185;
      const IP_Y_GAP = 75;
      const showIps = typeFilter === 'all' || typeFilter === 'ip';
      const domainRows = Math.ceil(visibleDomains.length / DOMAIN_COLS);
      const ipStartY = typeFilter === 'ip' ? 0 : 140 + domainRows * DOMAIN_Y_GAP + 60;
      const visibleIps = showIps ? ips : [];

      visibleIps.forEach((ip, i) => {
        const col = i % IP_COLS;
        const row = Math.floor(i / IP_COLS);
        const colsInThisRow = Math.min(IP_COLS, visibleIps.length - row * IP_COLS);
        const xOffset = (col - (colsInThisRow - 1) / 2) * IP_X_GAP;
        const yOffset = ipStartY + row * IP_Y_GAP;

        const isMatch =
          !query ||
          ip.value.toLowerCase().includes(query) ||
          (ip.metadata?.domain && ip.metadata.domain.toLowerCase().includes(query));
        const isSelected = activeNodeId === `ip-${ip.id}`;

        newNodes.push({
          id: `ip-${ip.id}`,
          data: {
            label: ip.value,
            asset: ip,
            assetType: 'ip',
            domain: ip.metadata?.domain,
          },
          position: { x: xOffset, y: yOffset },
          type: 'ip',
          selected: isSelected,
          style: { opacity: isMatch ? 1 : 0.2 },
        });

        const parentDomain = domains.find((d) => d.value === ip.metadata?.domain);
        if (parentDomain && showDomains) {
          newEdges.push({
            id: `e-d-${parentDomain.id}-ip-${ip.id}`,
            source: `d-${parentDomain.id}`,
            target: `ip-${ip.id}`,
            type: 'smoothstep',
            animated: isSelected,
            style: {
              stroke: isSelected ? '#8fb8ff' : 'rgba(143, 184, 255, 0.22)',
              strokeWidth: isSelected ? 2 : 1,
              opacity: isMatch ? 1 : 0.1,
            },
          });
        } else if (showRoot) {
          newEdges.push({
            id: `e-root-ip-${ip.id}`,
            source: 'root',
            target: `ip-${ip.id}`,
            type: 'smoothstep',
            style: {
              stroke: 'rgba(255, 255, 255, 0.08)',
              strokeWidth: 1,
              opacity: isMatch ? 1 : 0.05,
            },
          });
        }
      });

      // 3. Ports layout (Centered row)
      const showPorts = typeFilter === 'all' || typeFilter === 'port';
      const ipRows = Math.ceil(visibleIps.length / IP_COLS);
      const portStartY = typeFilter === 'port' ? 0 : ipStartY + ipRows * IP_Y_GAP + 60;
      const visiblePorts = showPorts ? ports : [];
      const PORT_GAP = 210;

      visiblePorts.forEach((p, i) => {
        const xOffset = (i - (visiblePorts.length - 1) / 2) * PORT_GAP;
        const yOffset = portStartY;

        const isMatch =
          !query ||
          p.value.toLowerCase().includes(query) ||
          (p.metadata?.service && p.metadata.service.toLowerCase().includes(query)) ||
          (p.metadata?.product && p.metadata.product.toLowerCase().includes(query));
        const isSelected = activeNodeId === `p-${p.id}`;

        newNodes.push({
          id: `p-${p.id}`,
          data: {
            label: p.value,
            asset: p,
            assetType: 'port',
            service: p.metadata?.service,
            product: p.metadata?.product,
            version: p.metadata?.version,
          },
          position: { x: xOffset, y: yOffset },
          type: 'port',
          selected: isSelected,
          style: { opacity: isMatch ? 1 : 0.2 },
        });

        if (showRoot) {
          newEdges.push({
            id: `e-root-p-${p.id}`,
            source: 'root',
            target: `p-${p.id}`,
            type: 'smoothstep',
            style: {
              stroke: isSelected ? '#ffd64d' : 'rgba(255, 214, 77, 0.22)',
              strokeWidth: isSelected ? 2 : 1,
              opacity: isMatch ? 1 : 0.1,
            },
          });
        }
      });

      // 4. Technologies layout (Centered row)
      const showTechs = typeFilter === 'all' || typeFilter === 'tech';
      const techStartY = typeFilter === 'tech' ? 0 : portStartY + (showPorts ? 100 : 0);
      const visibleTechs = showTechs ? techs : [];
      const TECH_GAP = 195;

      visibleTechs.forEach((t, i) => {
        const xOffset = (i - (visibleTechs.length - 1) / 2) * TECH_GAP;
        const yOffset = techStartY;

        const isMatch =
          !query ||
          t.value.toLowerCase().includes(query) ||
          (t.metadata?.version && t.metadata.version.toLowerCase().includes(query));
        const isSelected = activeNodeId === `t-${t.id}`;

        newNodes.push({
          id: `t-${t.id}`,
          data: {
            label: t.value,
            asset: t,
            assetType: 'tech',
            version: t.metadata?.version,
          },
          position: { x: xOffset, y: yOffset },
          type: 'tech',
          selected: isSelected,
          style: { opacity: isMatch ? 1 : 0.2 },
        });

        if (showRoot) {
          newEdges.push({
            id: `e-root-t-${t.id}`,
            source: 'root',
            target: `t-${t.id}`,
            type: 'smoothstep',
            style: {
              stroke: isSelected ? '#c084fc' : 'rgba(192, 132, 252, 0.22)',
              strokeWidth: isSelected ? 2 : 1,
              opacity: isMatch ? 1 : 0.1,
            },
          });
        }
      });

      setNodes(newNodes);
      setEdges(newEdges);
    },
    [setNodes, setEdges]
  );

  useEffect(() => {
    if (assets.length > 0) {
      buildTopology(assets, filterType, graphSearch, selectedNodeId);
    }
  }, [assets, filterType, graphSearch, selectedNodeId, buildTopology]);

  // Counts
  const counts = useMemo(() => {
    const res: Record<string, number> = { domain: 0, ip: 0, port: 0, tech: 0 };
    assets.forEach((a) => {
      if (res[a.type] !== undefined) res[a.type] += 1;
    });
    return res;
  }, [assets]);

  const total = assets.length;

  // Filtered assets for the table
  const filteredTableAssets = useMemo(() => {
    let list = assets;
    if (filterType !== 'all') {
      list = list.filter((a) => a.type === filterType);
    }
    if (tableSearch.trim()) {
      const q = tableSearch.toLowerCase();
      list = list.filter(
        (a) =>
          a.value.toLowerCase().includes(q) ||
          (a.metadata?.service && a.metadata.service.toLowerCase().includes(q)) ||
          (a.metadata?.product && a.metadata.product.toLowerCase().includes(q)) ||
          (a.metadata?.domain && a.metadata.domain.toLowerCase().includes(q))
      );
    }
    return list;
  }, [assets, filterType, tableSearch]);

  const handleSelectNode = (node: Node | null) => {
    if (!node) {
      setSelectedNodeId(null);
      setSelectedAsset(null);
      return;
    }
    setSelectedNodeId(node.id);
    if (node.data?.asset) {
      setSelectedAsset(node.data.asset);
    } else if (node.id === 'root') {
      setSelectedAsset({
        type: 'Apex Scope',
        value: 'worldmonitor.app',
        metadata: { status: 'authorized', assets: total },
      });
    }
  };

  const handleSelectAssetFromTable = (a: any) => {
    setSelectedAsset(a);
    const targetId =
      a.type === 'domain'
        ? `d-${a.id}`
        : a.type === 'ip'
        ? `ip-${a.id}`
        : a.type === 'port'
        ? `p-${a.id}`
        : a.type === 'tech'
        ? `t-${a.id}`
        : null;
    if (targetId) {
      setSelectedNodeId(targetId);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Operations / Assets"
        title="Attack surface graph"
        description="Discovered target landscape: domains, IPs, services, and running technologies. All nodes come from persisted observations."
      />

      {/* Metric Tiles / Layer Filter Bar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <StatTile
          icon={<Shield className="w-4 h-4 text-accent" />}
          label="Total assets"
          value={total}
          active={filterType === 'all'}
          onClick={() => setFilterType('all')}
        />
        <StatTile
          icon={<Globe className="w-4 h-4 text-low" />}
          label="Domains"
          value={counts.domain}
          active={filterType === 'domain'}
          onClick={() => setFilterType(filterType === 'domain' ? 'all' : 'domain')}
          badgeColor="text-low"
        />
        <StatTile
          icon={<Server className="w-4 h-4 text-emerald-400" />}
          label="IPs"
          value={counts.ip}
          active={filterType === 'ip'}
          onClick={() => setFilterType(filterType === 'ip' ? 'all' : 'ip')}
          badgeColor="text-emerald-400"
        />
        <StatTile
          icon={<Cable className="w-4 h-4 text-medium" />}
          label="Ports"
          value={counts.port}
          active={filterType === 'port'}
          onClick={() => setFilterType(filterType === 'port' ? 'all' : 'port')}
          badgeColor="text-medium"
        />
        <StatTile
          icon={<Cpu className="w-4 h-4 text-purple-400" />}
          label="Technologies"
          value={counts.tech}
          active={filterType === 'tech'}
          onClick={() => setFilterType(filterType === 'tech' ? 'all' : 'tech')}
          badgeColor="text-purple-400"
        />
      </div>

      {/* Main Split Layout: Topology Graph (Left) & Discovered Assets Table (Right) */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        {/* Topology Card */}
        <div
          className={`panel flex flex-col overflow-hidden transition-all duration-300 ${
            isFullscreen
              ? 'fixed inset-4 z-[70] h-[calc(100vh-2rem)] shadow-2xl backdrop-blur-2xl'
              : 'xl:col-span-8 h-[620px]'
          }`}
        >
          {/* Header */}
          <div className="flex shrink-0 items-center justify-between border-b border-line px-5 py-3.5 bg-surface-2/40">
            <div className="flex items-center gap-2.5">
              <span className="flex h-6 w-6 items-center justify-center rounded-lg border border-line bg-surface text-accent">
                <Crosshair className="h-3.5 w-3.5" />
              </span>
              <div>
                <h2 className="text-[13px] font-semibold text-text">Topology Map</h2>
              </div>
              <span className="mono-cell rounded-full border border-line bg-surface px-2 py-0.5 text-[9.5px] text-faint">
                {nodes.length} nodes
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="hidden sm:inline-flex text-[10.5px] text-faint font-mono">
                scroll to zoom · drag to pan
              </span>
              <button
                onClick={() => setIsFullscreen(!isFullscreen)}
                className="flex h-7 w-7 items-center justify-center rounded-lg border border-line bg-surface text-muted transition-colors hover:border-line-strong hover:text-text"
                title={isFullscreen ? 'Exit Fullscreen' : 'Expand Fullscreen'}
              >
                {isFullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
              </button>
            </div>
          </div>

          {/* Graph Body */}
          <div className="relative min-h-0 flex-1 overflow-hidden bg-bg">
            {total === 0 && !loading ? (
              <EmptyState
                icon={<Boxes className="w-5 h-5 text-faint" aria-hidden="true" />}
                title="No assets discovered"
                description="Run an assessment to start mapping the target surface."
              />
            ) : (
              <ReactFlowProvider>
                <FlowCanvas
                  nodes={nodes}
                  edges={edges}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onSelectNode={handleSelectNode}
                  selectedAsset={selectedAsset}
                  onCloseInspector={() => {
                    setSelectedAsset(null);
                    setSelectedNodeId(null);
                  }}
                  filterType={filterType}
                  setFilterType={setFilterType}
                  searchQuery={graphSearch}
                  setSearchQuery={setGraphSearch}
                  isFullscreen={isFullscreen}
                  setIsFullscreen={setIsFullscreen}
                  totalAssets={total}
                />
              </ReactFlowProvider>
            )}
          </div>
        </div>

        {/* Discovered Assets Card */}
        <div className={`xl:col-span-4 h-[620px] panel flex flex-col overflow-hidden ${isFullscreen ? 'hidden' : ''}`}>
          {/* Table Header with Search */}
          <div className="shrink-0 border-b border-line px-5 py-3.5 bg-surface-2/40">
            <div className="flex items-center justify-between gap-2 mb-2.5">
              <div className="flex items-center gap-2">
                <span className="flex h-6 w-6 items-center justify-center rounded-lg border border-line bg-surface text-muted">
                  <Layers className="h-3.5 w-3.5" />
                </span>
                <h2 className="text-[13px] font-semibold text-text">Discovered Assets</h2>
              </div>
              <span className="mono-cell rounded-full border border-line bg-surface px-2 py-0.5 text-[9.5px] text-faint">
                {filteredTableAssets.length} shown
              </span>
            </div>

            {/* Quick search input */}
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-faint" />
              <input
                type="text"
                value={tableSearch}
                onChange={(e) => setTableSearch(e.target.value)}
                placeholder="Filter table (url, ip, service)..."
                className="w-full rounded-xl border border-line bg-surface px-8 py-1.5 text-[11px] text-text placeholder:text-faint focus:border-accent/60 focus:outline-none"
              />
              {tableSearch && (
                <button
                  onClick={() => setTableSearch('')}
                  className="absolute right-2.5 top-2 text-faint hover:text-text"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Table Body */}
          <div className="min-h-0 flex-1 overflow-y-auto scrollbar-thin">
            <DataTable
              loading={loading}
              error={error}
              onRetry={fetchAssets}
              rows={filteredTableAssets}
              keyField={(a: any) => String(a.id)}
              onRowClick={(a: any) => handleSelectAssetFromTable(a)}
              empty={{
                title: 'No matching assets',
                description: 'Try adjusting the search filter or run a new scan.',
              }}
              columns={[
                {
                  key: 'value',
                  label: 'Asset',
                  render: (a: any) => {
                    const isSelected = selectedAsset?.id === a.id;
                    return (
                      <div className="min-w-0 flex items-center gap-2">
                        <span className={`shrink-0 ${isSelected ? 'text-accent' : 'text-faint'}`}>
                          {TYPE_ICON[a.type] ?? <Server className="w-3.5 h-3.5" aria-hidden="true" />}
                        </span>
                        <div className="min-w-0 flex-1">
                          <p
                            className={`font-mono text-[11px] truncate transition-colors ${
                              isSelected ? 'text-accent font-semibold' : 'text-text'
                            }`}
                            title={a.value}
                          >
                            {a.value}
                          </p>
                          {a.metadata?.domain && (
                            <p className="font-mono text-[9px] text-faint truncate">
                              ↳ {a.metadata.domain}
                            </p>
                          )}
                        </div>
                      </div>
                    );
                  },
                },
                {
                  key: 'type',
                  label: 'Type',
                  render: (a: any) => (
                    <span
                      className={`mono-cell rounded-md border px-1.5 py-0.5 text-[9.5px] capitalize ${
                        a.type === 'domain'
                          ? 'border-low/40 bg-low/10 text-low'
                          : a.type === 'ip'
                          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                          : a.type === 'port'
                          ? 'border-medium/40 bg-medium/10 text-medium'
                          : 'border-purple-500/40 bg-purple-500/10 text-purple-400'
                      }`}
                    >
                      {a.type}
                    </span>
                  ),
                },
                {
                  key: 'service',
                  label: 'Details',
                  render: (a: any) => {
                    const detail = a.metadata?.service || a.metadata?.product || a.metadata?.version || a.metadata?.status;
                    return detail ? (
                      <span className="mono-cell text-[10px] text-muted truncate max-w-[100px] block" title={detail}>
                        {detail}
                      </span>
                    ) : (
                      <span className="text-faint text-[10px]">—</span>
                    );
                  },
                },
              ]}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

/* ------------------------------------------------------------------------- */
/* Interactive Metric Tile Component                                         */
/* ------------------------------------------------------------------------- */

const StatTile: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: number;
  active?: boolean;
  onClick?: () => void;
  badgeColor?: string;
}> = ({ icon, label, value, active, onClick, badgeColor = 'text-accent' }) => (
  <button
    type="button"
    onClick={onClick}
    className={`panel relative overflow-hidden p-4 text-left transition-all duration-300 cursor-pointer ${
      active
        ? 'border-accent/60 bg-accent/[0.04] shadow-[0_0_20px_rgba(232,255,61,0.08)]'
        : 'hover:border-line-strong hover:bg-white/[0.02]'
    }`}
  >
    <div className="flex items-center justify-between mb-2">
      <p className="eyebrow">{label}</p>
      <span className="shrink-0">{icon}</span>
    </div>
    <p className={`tnum text-[26px] font-semibold leading-none tracking-tight text-text`}>
      {value}
    </p>
  </button>
);

export default Assets;