import { useEffect, useRef, useState, type DragEvent, type FormEvent } from "react";
import { fetchLatestIocReport, uploadIocReport, type LatestIocResponse } from "../api/client";
import IocReportEventExplorer from "../components/IocReportEventExplorer";
import ProcessTreeAccordion from "../components/ProcessTreeAccordion";
import SkeletonBlock from "../components/SkeletonBlock";
import { useToast } from "../components/ToastProvider";

function IocReportsPage() {
  const [latest, setLatest] = useState<LatestIocResponse | null>(null);
  const [loadingLatest, setLoadingLatest] = useState<boolean>(true);
  const [error, setError] = useState<string>("");
  const [uploading, setUploading] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropzoneRef = useRef<HTMLDivElement>(null);
  const { addToast } = useToast();

  const processCount = latest?.process_events.length ?? latest?.process_count ?? 0;
  const networkCount = latest?.network_events.length ?? latest?.flagged_connection_count ?? 0;
  const reportSize = latest?.report ? JSON.stringify(latest.report).length : 0;

  async function loadLatest() {
    setLoadingLatest(true);
    setError("");
    try {
      const data = await fetchLatestIocReport();
      setLatest(data);
    } catch (err) {
      const message = String(err);
      setLatest(null);
      setError(message);
      addToast({
        title: "Report Load Failed",
        message,
        tone: "error"
      });
    } finally {
      setLoadingLatest(false);
    }
  }

  useEffect(() => {
    void loadLatest();
  }, []);

  useEffect(() => {
    function handleShortcut(event: KeyboardEvent) {
      const key = event.key.toLowerCase();

      if (event.ctrlKey && event.shiftKey && key === "u") {
        event.preventDefault();
        fileInputRef.current?.click();
        return;
      }

      if (event.altKey && key === "d") {
        event.preventDefault();
        dropzoneRef.current?.focus();
        return;
      }

      if (event.altKey && key === "x") {
        event.preventDefault();
        setSelectedFile(null);
        if (fileInputRef.current) {
          fileInputRef.current.value = "";
        }
      }
    }

    window.addEventListener("keydown", handleShortcut);
    return () => {
      window.removeEventListener("keydown", handleShortcut);
    };
  }, []);

  async function uploadSelectedFile(file: File | null) {
    if (!file) {
      setError("Select an IOC report JSON file first.");
      addToast({
        title: "Upload Blocked",
        message: "Select an IOC report JSON file first.",
        tone: "warning"
      });
      return;
    }

    setUploading(true);
    setError("");
    try {
      await uploadIocReport(file);
      await loadLatest();
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
      addToast({
        title: "IOC Report Uploaded",
        message: file.name,
        tone: "success"
      });
    } catch (err) {
      const message = String(err);
      setError(message);
      addToast({
        title: "Upload Failed",
        message,
        tone: "error"
      });
    } finally {
      setUploading(false);
    }
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await uploadSelectedFile(selectedFile);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragging(false);

    const file = event.dataTransfer.files?.[0];
    if (!file) {
      return;
    }

    if (!file.name.toLowerCase().endsWith(".json")) {
      setError("Only JSON report files are accepted.");
      addToast({
        title: "Invalid File Type",
        message: "Drop a .json IOC report file.",
        tone: "warning"
      });
      return;
    }

    setError("");
    setSelectedFile(file);
  }

  return (
    <section className="main-dashboard panel-reveal">
      <header className="dashboard-header">
        <p className="eyebrow">IOC Reports</p>
        <h2>Upload and Review Latest Report</h2>
      </header>

      <form className="upload-form" onSubmit={handleUpload}>
        <input
          ref={fileInputRef}
          name="report"
          type="file"
          accept="application/json,.json"
          className="visually-hidden"
          onChange={(event) => {
            const file = event.target.files?.[0] ?? null;
            setSelectedFile(file);
            if (file) {
              setError("");
            }
          }}
        />

        <div
          ref={dropzoneRef}
          className={isDragging ? "upload-dropzone drag-active" : "upload-dropzone"}
          role="button"
          tabIndex={0}
          aria-label="IOC report upload dropzone"
          aria-describedby="ioc-dropzone-help ioc-file-status"
          aria-keyshortcuts="Control+Shift+U Alt+D Alt+X"
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              fileInputRef.current?.click();
              return;
            }

            if (event.key === "Backspace" || event.key === "Delete") {
              event.preventDefault();
              setSelectedFile(null);
              if (fileInputRef.current) {
                fileInputRef.current.value = "";
              }
            }
          }}
          onDragEnter={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={(event) => {
            event.preventDefault();
            setIsDragging(false);
          }}
          onDrop={handleDrop}
        >
          <p className="upload-dropzone-title">Drag and drop IOC JSON report here</p>
          <p className="muted-text">or click to browse</p>
          <p id="ioc-file-status" className="upload-filename" aria-live="polite">
            {selectedFile?.name ?? "No file selected"}
          </p>
          <p id="ioc-dropzone-help" className="dropzone-help muted-text">
            Shortcuts: Ctrl+Shift+U open file picker, Alt+D focus dropzone, Alt+X clear selection.
          </p>
        </div>

        <button className="tool-action" type="submit" disabled={uploading}>
          {uploading ? "Uploading..." : "Upload IOC Report"}
        </button>
      </form>

      {error ? <p className="error-text">{error}</p> : null}

      <div className="metric-grid">
        <article className="metric-card panel-reveal">
          <p className="metric-label">Source File</p>
          <p className="metric-value metric-value-small">
            {loadingLatest ? <SkeletonBlock className="skeleton-inline" /> : latest?.source_name ?? "N/A"}
          </p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Process Count</p>
          <p className="metric-value">{loadingLatest ? <SkeletonBlock className="skeleton-inline" /> : processCount}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Flagged Connections</p>
          <p className="metric-value">{loadingLatest ? <SkeletonBlock className="skeleton-inline" /> : networkCount}</p>
        </article>
        <article className="metric-card panel-reveal">
          <p className="metric-label">Report Size</p>
          <p className="metric-value metric-value-small">
            {loadingLatest ? <SkeletonBlock className="skeleton-inline" /> : reportSize ? `${reportSize} chars` : "N/A"}
          </p>
        </article>
      </div>

      <div className="report-meta-grid">
        <article className="meta-card panel-reveal">
          <p className="metric-label">Uploaded At</p>
          <p className="metric-value metric-value-small">
            {loadingLatest ? <SkeletonBlock className="skeleton-inline" /> : latest?.uploaded_at_utc ?? "N/A"}
          </p>
        </article>
        <article className="meta-card panel-reveal">
          <p className="metric-label">Raw Process Tree Nodes</p>
          <p className="metric-value">
            {loadingLatest ? <SkeletonBlock className="skeleton-inline" /> : latest?.process_tree.length ?? 0}
          </p>
        </article>
        <article className="meta-card panel-reveal">
          <p className="metric-label">Process Events</p>
          <p className="metric-value">{loadingLatest ? <SkeletonBlock className="skeleton-inline" /> : processCount}</p>
        </article>
        <article className="meta-card panel-reveal">
          <p className="metric-label">Network Events</p>
          <p className="metric-value">
            {loadingLatest ? <SkeletonBlock className="skeleton-inline" /> : latest?.network_events.length ?? 0}
          </p>
        </article>
      </div>

      <ProcessTreeAccordion nodes={latest?.process_tree ?? []} />

      <IocReportEventExplorer />
    </section>
  );
}

export default IocReportsPage;