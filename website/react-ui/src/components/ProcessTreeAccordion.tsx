import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import gsap from "gsap";

type RawProcessTreeNode = {
  pid?: number | string;
  ppid?: number | string;
  name?: string;
  process_name?: string;
  image?: string;
  cmdline?: unknown;
  command_line?: string;
  children?: RawProcessTreeNode[];
};

type TreeNodeData = {
  id: string;
  parentId: string | null;
  label: string;
  commandLine: string;
  children: TreeNodeData[];
};

type ProcessTreeAccordionProps = {
  nodes: Array<Record<string, unknown>>;
};

function toCommandLine(node: RawProcessTreeNode) {
  if (Array.isArray(node.cmdline)) {
    const value = node.cmdline.map((item) => String(item)).filter(Boolean).join(" ");
    if (value) {
      return value;
    }
  }

  if (typeof node.command_line === "string" && node.command_line.trim()) {
    return node.command_line;
  }

  if (typeof node.cmdline === "string" && node.cmdline.trim()) {
    return node.cmdline;
  }

  return "";
}

function toNodeLabel(node: RawProcessTreeNode) {
  const name = node.name ?? node.process_name ?? node.image ?? "unknown";
  const pid = Number(node.pid) || 0;
  const ppid = Number(node.ppid) || 0;
  return `${name} (PID ${pid}, PPID ${ppid})`;
}

function normalizeNode(node: RawProcessTreeNode, index: number, parentId: string | null): TreeNodeData {
  const id = parentId ? `${parentId}.${index + 1}` : `root-${index + 1}`;
  const children = Array.isArray(node.children) ? node.children : [];

  return {
    id,
    parentId,
    label: toNodeLabel(node),
    commandLine: toCommandLine(node),
    children: children.map((child, childIndex) => normalizeNode(child, childIndex, id))
  };
}

function flattenVisible(nodes: TreeNodeData[], expanded: Set<string>) {
  const result: TreeNodeData[] = [];

  function visit(list: TreeNodeData[]) {
    for (const node of list) {
      result.push(node);
      if (node.children.length > 0 && expanded.has(node.id)) {
        visit(node.children);
      }
    }
  }

  visit(nodes);
  return result;
}

type TreeItemProps = {
  node: TreeNodeData;
  depth: number;
  expanded: Set<string>;
  activeId: string;
  setActiveId: (id: string) => void;
  toggleNode: (id: string) => void;
  onKeyDown: (event: ReactKeyboardEvent<HTMLButtonElement>, node: TreeNodeData) => void;
  registerButtonRef: (id: string, element: HTMLButtonElement | null) => void;
};

function TreeItem({
  node,
  depth,
  expanded,
  activeId,
  setActiveId,
  toggleNode,
  onKeyDown,
  registerButtonRef
}: TreeItemProps) {
  const hasChildren = node.children.length > 0;
  const isExpanded = hasChildren ? expanded.has(node.id) : false;
  const isActive = activeId === node.id;
  const groupRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!hasChildren || !groupRef.current) {
      return;
    }

    const element = groupRef.current;
    gsap.killTweensOf(element);

    if (isExpanded) {
      element.style.display = "grid";
      gsap.fromTo(
        element,
        { height: 0, opacity: 0 },
        {
          height: element.scrollHeight,
          opacity: 1,
          duration: 0.24,
          ease: "power2.out",
          onComplete: () => {
            element.style.height = "auto";
          }
        }
      );
    } else {
      gsap.fromTo(
        element,
        { height: element.offsetHeight, opacity: 1 },
        {
          height: 0,
          opacity: 0,
          duration: 0.2,
          ease: "power2.in",
          onComplete: () => {
            element.style.display = "none";
          }
        }
      );
    }
  }, [hasChildren, isExpanded]);

  return (
    <article className="process-tree-node" data-depth={depth} role="treeitem" aria-level={depth + 1} aria-expanded={hasChildren ? isExpanded : undefined}>
      <div className="process-tree-header-row">
        {hasChildren ? (
          <button
            type="button"
            className="process-tree-toggle"
            aria-label={isExpanded ? "Collapse node" : "Expand node"}
            onClick={() => toggleNode(node.id)}
            tabIndex={-1}
          >
            {isExpanded ? "-" : "+"}
          </button>
        ) : (
          <span className="process-tree-toggle-spacer" aria-hidden="true" />
        )}

        <button
          ref={(element) => registerButtonRef(node.id, element)}
          id={`tree-label-${node.id}`}
          type="button"
          className={isActive ? "process-tree-label active" : "process-tree-label"}
          tabIndex={isActive ? 0 : -1}
          onFocus={() => setActiveId(node.id)}
          onKeyDown={(event) => onKeyDown(event, node)}
          onClick={() => {
            setActiveId(node.id);
            if (hasChildren) {
              toggleNode(node.id);
            }
          }}
        >
          {node.label}
        </button>
      </div>

      {node.commandLine ? <p className="process-tree-cmdline">{node.commandLine}</p> : null}

      {hasChildren ? (
        <div
          ref={groupRef}
          className="process-tree-children"
          role="group"
          style={{ display: isExpanded ? "grid" : "none" }}
        >
          {node.children.map((child) => (
            <TreeItem
              key={child.id}
              node={child}
              depth={depth + 1}
              expanded={expanded}
              activeId={activeId}
              setActiveId={setActiveId}
              toggleNode={toggleNode}
              onKeyDown={onKeyDown}
              registerButtonRef={registerButtonRef}
            />
          ))}
        </div>
      ) : null}
    </article>
  );
}

function ProcessTreeAccordion({ nodes }: ProcessTreeAccordionProps) {
  const treeData = useMemo(
    () => nodes.map((node, index) => normalizeNode(node as RawProcessTreeNode, index, null)),
    [nodes]
  );
  const rootIds = useMemo(() => treeData.map((node) => node.id), [treeData]);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set(rootIds));
  const [activeId, setActiveId] = useState<string>(rootIds[0] ?? "");
  const labelRefs = useRef<Map<string, HTMLButtonElement>>(new Map());

  useEffect(() => {
    setExpandedIds(new Set(rootIds));
    setActiveId(rootIds[0] ?? "");
  }, [rootIds.join("|")]);

  const visibleNodes = useMemo(() => flattenVisible(treeData, expandedIds), [treeData, expandedIds]);
  const visibleIds = useMemo(() => visibleNodes.map((node) => node.id), [visibleNodes]);
  const nodeMap = useMemo(() => {
    const map = new Map<string, TreeNodeData>();

    function add(node: TreeNodeData) {
      map.set(node.id, node);
      node.children.forEach(add);
    }

    treeData.forEach(add);
    return map;
  }, [treeData]);

  const focusNode = (id: string) => {
    setActiveId(id);
    requestAnimationFrame(() => {
      labelRefs.current.get(id)?.focus();
    });
  };

  const registerButtonRef = (id: string, element: HTMLButtonElement | null) => {
    if (!element) {
      labelRefs.current.delete(id);
      return;
    }
    labelRefs.current.set(id, element);
  };

  const toggleNode = (id: string) => {
    setExpandedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  function handleNodeKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>, node: TreeNodeData) {
    const currentIndex = visibleIds.indexOf(node.id);
    const hasChildren = node.children.length > 0;
    const isExpanded = expandedIds.has(node.id);

    if (event.key === "ArrowDown") {
      event.preventDefault();
      const nextId = visibleIds[Math.min(currentIndex + 1, visibleIds.length - 1)];
      if (nextId) {
        focusNode(nextId);
      }
      return;
    }

    if (event.key === "ArrowUp") {
      event.preventDefault();
      const prevId = visibleIds[Math.max(currentIndex - 1, 0)];
      if (prevId) {
        focusNode(prevId);
      }
      return;
    }

    if (event.key === "Home") {
      event.preventDefault();
      if (visibleIds[0]) {
        focusNode(visibleIds[0]);
      }
      return;
    }

    if (event.key === "End") {
      event.preventDefault();
      const lastId = visibleIds[visibleIds.length - 1];
      if (lastId) {
        focusNode(lastId);
      }
      return;
    }

    if (event.key === "ArrowRight") {
      event.preventDefault();
      if (hasChildren && !isExpanded) {
        toggleNode(node.id);
      } else if (hasChildren && node.children[0]) {
        focusNode(node.children[0].id);
      }
      return;
    }

    if (event.key === "ArrowLeft") {
      event.preventDefault();
      if (hasChildren && isExpanded) {
        toggleNode(node.id);
      } else if (node.parentId) {
        focusNode(node.parentId);
      }
      return;
    }

    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (hasChildren) {
        toggleNode(node.id);
      }
    }
  }

  if (treeData.length === 0) {
    return <p className="muted-text">No process tree data found in this report.</p>;
  }

  return (
    <section className="process-tree-panel glass-panel panel-reveal" aria-label="Process tree explorer">
      <header className="dashboard-header">
        <p className="eyebrow">Process Tree Explorer</p>
        <h3>Collapsible Execution Chain</h3>
        <p className="muted-text process-tree-shortcuts">
          Keyboard: Up/Down move, Left/Right collapse or expand, Home/End jump, Enter toggles nodes.
        </p>
      </header>
      <div
        className="process-tree-root"
        role="tree"
        aria-label="IOC process tree"
        aria-activedescendant={activeId ? `tree-label-${activeId}` : undefined}
      >
        {treeData.map((node) => (
          <TreeItem
            key={node.id}
            node={node}
            depth={0}
            expanded={expandedIds}
            activeId={activeId}
            setActiveId={setActiveId}
            toggleNode={toggleNode}
            onKeyDown={handleNodeKeyDown}
            registerButtonRef={registerButtonRef}
          />
        ))}
      </div>
      <p className="visually-hidden" aria-live="polite">
        {activeId && nodeMap.get(activeId) ? `Focused node ${nodeMap.get(activeId)?.label}` : ""}
      </p>
    </section>
  );
}

export default ProcessTreeAccordion;