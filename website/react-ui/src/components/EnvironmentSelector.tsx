import { useState } from "react";
import { ENVIRONMENT_TEMPLATES } from "../data/detectionRuleTemplates";

type EnvironmentSelectorProps = {
  onApplyTemplate: (templateId: string) => void;
  isLoading?: boolean;
};

function EnvironmentSelector({ onApplyTemplate, isLoading }: EnvironmentSelectorProps) {
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  const handleApply = () => {
    if (!selectedTemplate) return;
    onApplyTemplate(selectedTemplate);
    setShowConfirm(false);
  };

  return (
    <section className="rounded-2xl border border-slate-700/60 bg-slate-900/70 p-6 shadow-[0_10px_40px_rgba(2,6,23,0.5)] backdrop-blur-xl">
      <div className="mb-6">
        <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-300 mb-2">
          Detection Rule Templates
        </h3>
        <p className="text-sm text-slate-400">
          Select a pre-configured ruleset optimized for your environment. This will replace your current rules.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 mb-6">
        {ENVIRONMENT_TEMPLATES.map((template) => (
          <button
            key={template.id}
            onClick={() => setSelectedTemplate(template.id)}
            className={`rounded-xl border-2 p-4 text-left transition ${
              selectedTemplate === template.id
                ? "border-purple-400 bg-purple-500/20"
                : "border-slate-700/60 bg-slate-950/70 hover:border-slate-600 hover:bg-slate-950"
            }`}
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-2xl mb-1">{template.icon}</p>
                <h4 className="font-semibold text-slate-100">{template.name}</h4>
                <p className="text-xs text-slate-400 mt-1">{template.description}</p>
              </div>
              <span className="text-sm font-semibold text-slate-400 bg-slate-800/50 rounded px-2 py-1">
                {template.rules.length} rules
              </span>
            </div>
          </button>
        ))}
      </div>

      {selectedTemplate && (
        <div className="rounded-lg border border-slate-700/50 bg-slate-950/70 p-4 mb-6">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">
            Selected Rules Preview
          </h4>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {ENVIRONMENT_TEMPLATES.find((t) => t.id === selectedTemplate)?.rules.map((rule) => (
              <div key={rule.id} className="flex items-center justify-between rounded bg-slate-900/50 px-3 py-2 text-xs">
                <span className="text-slate-300">{rule.name}</span>
                <span
                  className={`rounded px-2 py-1 text-xs font-semibold ${
                    rule.severity === "critical"
                      ? "bg-rose-500/20 text-rose-200"
                      : rule.severity === "high"
                        ? "bg-orange-500/20 text-orange-200"
                        : rule.severity === "medium"
                          ? "bg-amber-500/20 text-amber-200"
                          : "bg-blue-500/20 text-blue-200"
                  }`}
                >
                  {rule.severity.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => setShowConfirm(true)}
          disabled={!selectedTemplate || isLoading}
          className="flex-1 rounded-lg border border-purple-400/45 bg-purple-500/20 px-4 py-2 text-sm font-semibold text-purple-100 transition hover:bg-purple-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? "Applying..." : "Apply Template"}
        </button>
        <button
          type="button"
          onClick={() => setSelectedTemplate(null)}
          className="rounded-lg border border-slate-600/50 bg-slate-800/40 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:bg-slate-800/60"
        >
          Clear Selection
        </button>
      </div>

      {showConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-xl max-w-sm mx-4">
            <h3 className="text-lg font-semibold text-slate-100 mb-2">
              Apply Detection Rule Template?
            </h3>
            <p className="text-sm text-slate-400 mb-4">
              This will replace your current detection rules with the{" "}
              <strong>
                {ENVIRONMENT_TEMPLATES.find((t) => t.id === selectedTemplate)?.name}
              </strong>{" "}
              template. This action can be undone.
            </p>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={handleApply}
                className="flex-1 rounded-lg border border-purple-400/45 bg-purple-500/20 px-4 py-2 text-sm font-semibold text-purple-100 hover:bg-purple-500/30"
              >
                Apply Template
              </button>
              <button
                type="button"
                onClick={() => setShowConfirm(false)}
                className="flex-1 rounded-lg border border-slate-600/50 bg-slate-800/40 px-4 py-2 text-sm font-semibold text-slate-300 hover:bg-slate-800/60"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

export default EnvironmentSelector;
