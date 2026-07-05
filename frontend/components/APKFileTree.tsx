"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import { ChevronRight, ChevronDown, ChevronUp, Folder, FolderOpen, File, AlertTriangle, Package, List, GitBranch, Network, X, ZoomIn, ZoomOut, Maximize } from "lucide-react";

interface TreeNode {
  name: string;
  path: string;
  type: "file" | "dir";
  size?: number;
  ext?: string;
  suspicious?: boolean;
  warning?: string;
  children?: TreeNode[];
  virtual?: boolean;
}

interface FileTreeStats {
  total_files: number;
  total_size_bytes: number;
  dex_count: number;
  dex_files: string[];
  native_libs: number;
  suspicious_count: number;
  suspicious_files: string[];
}

interface FileTreeData {
  tree: TreeNode[];
  stats: FileTreeStats;
  error?: string | null;
}

const EXT_ICONS: Record<string, { icon: string; color: string }> = {
  ".dex": { icon: "⚙️", color: "text-blue-400" },
  ".so":  { icon: "🔧", color: "text-orange-400" },
  ".xml": { icon: "📋", color: "text-green-400" },
  ".png": { icon: "🖼️", color: "text-purple-400" },
  ".jpg": { icon: "🖼️", color: "text-purple-400" },
  ".json":{ icon: "📄", color: "text-yellow-400" },
  ".jar": { icon: "☕", color: "text-red-400" },
  ".bin": { icon: "💾", color: "text-rose-400" },
  ".enc": { icon: "🔒", color: "text-rose-500" },
  ".dat": { icon: "📦", color: "text-slate-200" },
};

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}

/* ─── List View (existing) ───────────────────────────────────────────── */

function TreeNodeView({
  node,
  depth = 0,
}: {
  node: TreeNode;
  depth?: number;
}) {
  const [open, setOpen] = useState(depth < 2);
  const isDir = node.type === "dir";
  const extInfo = node.ext ? EXT_ICONS[node.ext] : null;

  return (
    <div className={`select-none ${depth > 0 ? "ml-4" : ""}`}>
      <div
        className={`
          flex items-center gap-1.5 py-[3px] px-2 rounded-md cursor-pointer group
          transition-colors text-sm
          ${node.suspicious
            ? "bg-rose-500/8 hover:bg-rose-500/15 text-rose-300"
            : "hover:bg-slate-700/40 text-slate-300"
          }
        `}
        onClick={() => isDir && setOpen((o) => !o)}
      >
        {depth > 0 && (
          <span className="text-slate-300 select-none" style={{ marginLeft: `${(depth - 1) * 12}px` }} />
        )}

        {isDir ? (
          <span className="text-slate-300 w-3.5 flex-shrink-0">
            {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </span>
        ) : (
          <span className="w-3.5 flex-shrink-0" />
        )}

        {isDir ? (
          open ? (
            <FolderOpen className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0" />
          ) : (
            <Folder className="w-3.5 h-3.5 text-yellow-500 flex-shrink-0" />
          )
        ) : extInfo ? (
          <span className={`text-[11px] leading-none ${extInfo.color}`}>{extInfo.icon}</span>
        ) : (
          <File className="w-3 h-3 text-slate-300 flex-shrink-0" />
        )}

        <span className={`truncate font-mono text-xs ${node.suspicious ? "text-rose-300 font-semibold" : ""}`}>
          {node.name}
        </span>

        {node.size != null && (
          <span className="ml-auto text-[10px] text-slate-200 flex-shrink-0">
            {formatBytes(node.size)}
          </span>
        )}

        {node.suspicious && (
          <span className="ml-1 flex-shrink-0" title={node.warning}>
            <AlertTriangle className="w-3 h-3 text-rose-400" />
          </span>
        )}
      </div>

      {node.suspicious && node.warning && (
        <div className="ml-8 mb-1 text-[11px] text-rose-400/80 bg-rose-500/5 border border-rose-500/15 rounded px-2 py-1">
          ⚠️ {node.warning}
        </div>
      )}

      {isDir && open && node.children && node.children.length > 0 && (
        <div>
          {node.children.map((child) => (
            <TreeNodeView key={child.path} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

/* ─── Top-Down Flowchart Tree View ────────────────────────────────────────── */

// Helper to group massive file lists into virtual category folders
function groupChildren(children: TreeNode[]): TreeNode[] {
  const dirs = children.filter(c => c.type === "dir");
  const files = children.filter(c => c.type === "file");

  // If there are only a few files, no need to group them (prevents over-nesting small folders)
  if (files.length <= 5) {
    return children;
  }

  const groups: Record<string, TreeNode[]> = {
    "XML & Configs": [],
    "Images & Media": [],
    "Native Libs (.so)": [],
    "Executables (.dex)": [],
    "Certificates": [],
    "Other Files": []
  };

  files.forEach(f => {
    const ext = (f.ext || "").toLowerCase();
    const name = f.name.toLowerCase();
    
    if (ext === ".xml" || ext === ".json") groups["XML & Configs"].push(f);
    else if (ext === ".png" || ext === ".jpg" || ext === ".jpeg" || ext === ".webp" || ext === ".gif") groups["Images & Media"].push(f);
    else if (ext === ".so") groups["Native Libs (.so)"].push(f);
    else if (ext === ".dex" || ext === ".jar") groups["Executables (.dex)"].push(f);
    else if (ext === ".rsa" || ext === ".dsa" || ext === ".sf" || ext === ".mf" || name.endsWith(".rsa")) groups["Certificates"].push(f);
    else groups["Other Files"].push(f);
  });

  const virtualNodes: TreeNode[] = [];
  for (const [groupName, groupFiles] of Object.entries(groups)) {
    if (groupFiles.length > 0) {
      virtualNodes.push({
        name: `${groupName} (${groupFiles.length})`,
        path: `virtual-${groupName}-${Math.random()}`,
        type: "dir",
        virtual: true,
        children: groupFiles,
        suspicious: groupFiles.some(f => f.suspicious),
      });
    }
  }

  return [...dirs, ...virtualNodes];
}

function FlowchartNode({ node, depth = 0 }: { node: TreeNode; depth?: number }) {
  // Expand everything at starting
  const [expanded, setExpanded] = useState(true);
  const isDir = node.type === "dir";
  const extInfo = node.ext ? EXT_ICONS[node.ext] : null;

  // Group children to prevent infinite horizontal width (only for real directories)
  const displayChildren = (node.children && !node.virtual) ? groupChildren(node.children) : (node.children || []);

  return (
    <li className="relative float-left text-center list-none px-2 py-5 transition-all">
      {/* Node Card */}
      <div className="inline-flex flex-col items-center relative z-10">
        <div 
          className={`
            flex flex-col items-center justify-center px-3 py-2 rounded-lg border min-w-[100px] max-w-[140px]
            transition-all duration-300 shadow-xl backdrop-blur-sm
            ${node.suspicious 
              ? "bg-rose-950/90 border-rose-500 text-rose-200 shadow-[0_0_15px_rgba(244,63,94,0.4)]" 
              : node.virtual
                ? "bg-indigo-950/80 border-indigo-400/50 text-indigo-100 hover:bg-indigo-900/80 hover:border-indigo-400"
                : isDir 
                  ? "bg-slate-800/90 border-blue-500/40 text-slate-100 hover:border-blue-400 hover:bg-slate-700" 
                  : "bg-slate-800/50 border-slate-700/80 text-slate-300 hover:border-slate-500 hover:bg-slate-700"
            }
            ${isDir ? "cursor-pointer" : ""}
          `}
          onClick={() => isDir && setExpanded(!expanded)}
        >
          <div className="flex items-center gap-1.5 mb-1.5">
            {node.virtual ? (
              <Package className="w-5 h-5 flex-shrink-0 text-indigo-300" />
            ) : isDir ? (
              <FolderOpen className={`w-5 h-5 flex-shrink-0 ${node.suspicious ? "text-rose-400" : "text-yellow-400"}`} />
            ) : extInfo ? (
              <span className={`text-[16px] leading-none flex-shrink-0 ${extInfo.color}`}>{extInfo.icon}</span>
            ) : (
              <File className="w-4 h-4 text-slate-400 flex-shrink-0" />
            )}
            {node.suspicious && <span title={node.warning}><AlertTriangle className="w-4 h-4 text-rose-500 flex-shrink-0" /></span>}
          </div>
          
          <span 
            className="text-[10px] text-center font-mono w-full break-all leading-tight" 
            style={{ 
              display: "-webkit-box", 
              WebkitLineClamp: 3, 
              WebkitBoxOrient: "vertical", 
              overflow: "hidden" 
            }}
            title={node.name}
          >
            {node.name}
          </span>

          {!isDir && node.size != null && (
            <span className="text-[9px] text-slate-400 mt-1">{formatBytes(node.size)}</span>
          )}
          
          {node.virtual && expanded && node.children && (
            <div className="mt-3 w-full text-left border-t border-indigo-500/30 pt-2 flex flex-col gap-1.5">
              {node.children.map(f => {
                const fExtInfo = f.ext ? EXT_ICONS[f.ext] : null;
                return (
                  <div key={f.path} className="flex items-center gap-1.5 text-[10px] hover:bg-indigo-500/20 px-1 py-0.5 rounded truncate flex-shrink-0">
                    {fExtInfo ? (
                      <span className={`text-[12px] leading-none flex-shrink-0 ${fExtInfo.color}`}>{fExtInfo.icon}</span>
                    ) : (
                      <File className="w-3 h-3 flex-shrink-0 text-indigo-300" />
                    )}
                    <span className="truncate text-indigo-100" title={f.name}>{f.name}</span>
                  </div>
                );
              })}
            </div>
          )}

          {isDir && !node.virtual && displayChildren.length > 0 && (
            <div className="absolute -bottom-3 left-1/2 -translate-x-1/2 bg-slate-900 border border-slate-600 rounded-full p-0.5 text-slate-400 shadow-md hover:bg-slate-700 transition-colors">
              {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </div>
          )}
          {node.virtual && node.children && node.children.length > 0 && (
            <div className="absolute -bottom-3 left-1/2 -translate-x-1/2 bg-indigo-900 border border-indigo-500 rounded-full p-0.5 text-indigo-300 shadow-md hover:bg-indigo-800 transition-colors">
              {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </div>
          )}
        </div>
      </div>
      
      {/* Children */}
      {isDir && !node.virtual && expanded && displayChildren.length > 0 && (
        <ul className="flex justify-center pt-5 relative org-tree">
          {displayChildren.map((child) => (
            <FlowchartNode key={child.path} node={child} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

function FlowchartTreeView({ tree }: { tree: TreeNode[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [scale, setScale] = useState(1);
  const [isDragging, setIsDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0 });

  const rootNode: TreeNode = {
    name: "APK Root",
    path: "/",
    type: "dir",
    children: tree,
    suspicious: tree.some(n => n.suspicious)
  };

  const handlePointerDown = (e: React.PointerEvent) => {
    setIsDragging(true);
    dragStart.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  };

  const handlePointerMove = (e: React.PointerEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.current.x,
      y: e.clientY - dragStart.current.y
    });
  };

  const handlePointerUp = (e: React.PointerEvent) => {
    setIsDragging(false);
    (e.target as HTMLElement).releasePointerCapture(e.pointerId);
  };

  return (
    <div 
      className="relative w-full h-[600px] overflow-hidden bg-[rgba(15,23,42,0.8)] border-t border-slate-700/50"
    >
      {/* CSS for drawing the org-chart connecting lines using borders */}
      <style dangerouslySetInnerHTML={{__html: `
        .org-tree::before {
          content: '';
          position: absolute;
          top: 0;
          left: 50%;
          border-left: 1px solid #475569;
          width: 0;
          height: 20px;
        }
        .org-tree li::before, .org-tree li::after {
          content: '';
          position: absolute;
          top: 0;
          right: 50%;
          border-top: 1px solid #475569;
          width: 50%;
          height: 20px;
        }
        .org-tree li::after {
          right: auto;
          left: 50%;
          border-left: 1px solid #475569;
        }
        .org-tree li:only-child::after, .org-tree li:only-child::before {
          display: none;
        }
        .org-tree li:only-child {
          padding-top: 0;
        }
        .org-tree li:first-child::before, .org-tree li:last-child::after {
          border: 0 none;
        }
        .org-tree li:last-child::before {
          border-right: 1px solid #475569;
          border-radius: 0 5px 0 0;
        }
        .org-tree li:first-child::after {
          border-radius: 5px 0 0 0;
        }
      `}} />

      <div 
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: "radial-gradient(#475569 1px, transparent 1px)",
          backgroundSize: `${30 * scale}px ${30 * scale}px`,
          backgroundPosition: `${pan.x}px ${pan.y}px`
        }}
      />

      <div 
        ref={containerRef}
        className={`absolute inset-0 w-full h-full ${isDragging ? "cursor-grabbing" : "cursor-grab"} flex justify-center`}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onWheel={(e) => {
          if (e.ctrlKey || e.metaKey || e.altKey) {
            e.preventDefault();
            setScale(s => Math.min(Math.max(0.1, s - e.deltaY * 0.005), 3));
          }
        }}
      >
        {/* Panning & Scaling layer */}
        <div 
          className="absolute pt-10 px-20 pb-20 origin-top transition-transform duration-75" 
          style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${scale})` }}
        >
          <ul className="flex justify-center">
            <FlowchartNode node={rootNode} depth={0} />
          </ul>
        </div>
      </div>
      
      {/* Zoom Controls */}
      <div className="absolute top-4 right-4 flex flex-col gap-2 bg-slate-900/80 border border-slate-700/80 p-1.5 rounded-lg shadow-xl backdrop-blur-md z-50">
        <button 
          onClick={() => setScale(s => Math.min(s + 0.2, 3))}
          className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-700 rounded transition-colors"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button 
          onClick={() => { setScale(1); setPan({ x: 0, y: 0 }); }}
          className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-700 rounded transition-colors"
          title="Reset Zoom & Pan"
        >
          <Maximize className="w-4 h-4" />
        </button>
        <button 
          onClick={() => setScale(s => Math.max(s - 0.2, 0.1))}
          className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-700 rounded transition-colors"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
      </div>

      {/* Legend / Info */}
      <div className="absolute bottom-4 left-4 bg-black/50 border border-white/10 px-3 py-2 rounded-lg backdrop-blur-md pointer-events-none z-50">
        <p className="text-xs text-slate-300 font-mono flex flex-col gap-1">
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-500 inline-block animate-pulse"></span>
            Drag to pan. Click nodes to collapse/expand.
          </span>
          <span className="text-[10px] text-slate-400">Ctrl/Cmd + Scroll to zoom</span>
        </p>
      </div>
    </div>
  );
}

/* ─── Main Component ─────────────────────────────────────────────────── */

interface APKFileTreeProps {
  analysisId: string;
}

export default function APKFileTree({ analysisId }: APKFileTreeProps) {
  const [data, setData] = useState<FileTreeData | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [viewMode, setViewMode] = useState<"list" | "flowchart">("flowchart");

  const fetchTree = useCallback(async () => {
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || ""}/api/analysis/${analysisId}/filetree`
      );
      if (res.ok) setData(await res.json());
    } catch {
      setData({ tree: [], stats: {} as FileTreeStats, error: "Failed to load file tree" });
    } finally {
      setLoading(false);
    }
  }, [analysisId]);

  useEffect(() => { fetchTree(); }, [fetchTree]);

  if (loading) {
    return (
      <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6 animate-pulse">
        <div className="h-4 w-48 bg-slate-700/50 rounded mb-4" />
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="h-3 rounded bg-slate-800" style={{ width: `${60 + i * 5}%` }} />
          ))}
        </div>
      </div>
    );
  }

  if (!data || data.error) {
    return (
      <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6 text-center text-slate-300 text-sm">
        <Package className="w-8 h-8 mx-auto mb-2 text-slate-200" />
        {data?.error || "File tree unavailable"}
      </div>
    );
  }

  const stats = data.stats;

  return (
    <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 overflow-hidden">
      {/* Header */}
      <div className="border-b border-slate-700/40 px-5 py-4 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Folder className="w-4 h-4 text-yellow-400" />
          <span className="font-semibold text-slate-100 text-sm">APK File Structure</span>
          {stats.suspicious_count > 0 && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/25">
              ⚠️ {stats.suspicious_count} suspicious
            </span>
          )}
        </div>
        <div className="flex items-center gap-4">
          {/* View toggle */}
          <div className="flex items-center bg-slate-800/80 border border-slate-700/50 rounded-lg overflow-hidden">
            <button
              onClick={() => setViewMode("list")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[0.65rem] font-mono uppercase tracking-wider transition-all ${
                viewMode === "list"
                  ? "bg-white/10 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <List className="w-3 h-3" />
              List
            </button>
            <button
              onClick={() => setViewMode("flowchart")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[0.65rem] font-mono uppercase tracking-wider transition-all ${
                viewMode === "flowchart"
                  ? "bg-white/10 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Network className="w-3 h-3" />
              Flowchart
            </button>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-300">
            <span><span className="text-slate-300 font-semibold">{stats.total_files}</span> files</span>
            <span className="text-slate-300">·</span>
            <span><span className="text-blue-400 font-semibold">{stats.dex_count}</span> DEX</span>
            <span className="text-slate-300">·</span>
            <span><span className="text-orange-400 font-semibold">{stats.native_libs}</span> .so libs</span>
            <span className="text-slate-300">·</span>
            <span>{formatBytes(stats.total_size_bytes || 0)}</span>
          </div>
        </div>
      </div>

      {/* Suspicious files summary */}
      {stats.suspicious_count > 0 && (
        <div className="mx-4 mt-4 rounded-lg border border-rose-500/20 bg-rose-500/5 p-3">
          <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold mb-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            Suspicious Entries Detected
          </div>
          <div className="flex flex-wrap gap-1.5">
            {stats.suspicious_files?.map((f) => (
              <code key={f} className="text-[10px] bg-rose-500/10 text-rose-300 px-2 py-0.5 rounded font-mono">
                {f}
              </code>
            ))}
          </div>
        </div>
      )}

      {/* View content */}
      {viewMode === "list" ? (
        <>
          {/* Search */}
          <div className="px-4 pt-3 pb-2">
            <input
              type="text"
              placeholder="Filter files…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg text-xs bg-slate-800/80 border border-slate-700/50 text-slate-300 placeholder-slate-600 outline-none focus:border-indigo-500/40"
            />
          </div>

          {/* Tree */}
          <div className="px-3 pb-4 max-h-96 overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-slate-700">
            {data.tree.length === 0 ? (
              <p className="text-center text-slate-200 text-xs py-8">No files found</p>
            ) : (
              data.tree.map((node) => (
                <TreeNodeView key={node.path} node={node} depth={0} />
              ))
            )}
          </div>
        </>
      ) : (
        <FlowchartTreeView tree={data.tree} />
      )}
    </div>
  );
}
