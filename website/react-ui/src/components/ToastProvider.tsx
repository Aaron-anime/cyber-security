import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import gsap from "gsap";

type ToastTone = "info" | "success" | "warning" | "error";

type ToastItem = {
  id: number;
  title: string;
  message?: string;
  tone: ToastTone;
};

type AddToastInput = {
  title: string;
  message?: string;
  tone?: ToastTone;
  durationMs?: number;
};

type ToastContextValue = {
  addToast: (input: AddToastInput) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

function ToastViewport({
  toasts,
  onDismiss,
  registerToastElement
}: {
  toasts: ToastItem[];
  onDismiss: (id: number) => void;
  registerToastElement: (id: number, element: HTMLElement | null) => void;
}) {
  return (
    <div className="toast-viewport" role="region" aria-label="Notifications">
      {toasts.map((toast) => (
        <article
          key={toast.id}
          className={`toast-card toast-${toast.tone}`}
          role={toast.tone === "error" ? "alert" : "status"}
          ref={(element) => registerToastElement(toast.id, element)}
        >
          <div className="toast-header-row">
            <h4>{toast.title}</h4>
            <button
              type="button"
              className="toast-dismiss"
              onClick={() => onDismiss(toast.id)}
              aria-label="Dismiss notification"
            >
              x
            </button>
          </div>
          {toast.message ? <p>{toast.message}</p> : null}
        </article>
      ))}
    </div>
  );
}

function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const toastRefs = useRef<Map<number, HTMLElement>>(new Map());
  const timerRefs = useRef<Map<number, number>>(new Map());
  const exitingIdsRef = useRef<Set<number>>(new Set());

  const removeToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const dismissToast = useCallback(
    (id: number) => {
      if (exitingIdsRef.current.has(id)) {
        return;
      }
      exitingIdsRef.current.add(id);

      const pendingTimer = timerRefs.current.get(id);
      if (pendingTimer) {
        window.clearTimeout(pendingTimer);
        timerRefs.current.delete(id);
      }

      const element = toastRefs.current.get(id);
      if (!element) {
        exitingIdsRef.current.delete(id);
        removeToast(id);
        return;
      }

      gsap.killTweensOf(element);
      gsap.to(element, {
        x: 24,
        autoAlpha: 0,
        duration: 0.22,
        ease: "power2.in",
        onComplete: () => {
          exitingIdsRef.current.delete(id);
          toastRefs.current.delete(id);
          removeToast(id);
        }
      });
    },
    [removeToast]
  );

  const registerToastElement = useCallback((id: number, element: HTMLElement | null) => {
    if (!element) {
      toastRefs.current.delete(id);
      return;
    }

    toastRefs.current.set(id, element);
    gsap.fromTo(
      element,
      { y: -12, x: 20, autoAlpha: 0, scale: 0.98 },
      { y: 0, x: 0, autoAlpha: 1, scale: 1, duration: 0.3, ease: "power2.out" }
    );
  }, []);

  const addToast = useCallback(
    ({ title, message, tone = "info", durationMs = 4200 }: AddToastInput) => {
      const id = Date.now() + Math.floor(Math.random() * 1000);
      setToasts((current) => [...current, { id, title, message, tone }]);

      const timerId = window.setTimeout(() => {
        timerRefs.current.delete(id);
        dismissToast(id);
      }, durationMs);
      timerRefs.current.set(id, timerId);
    },
    [dismissToast]
  );

  useEffect(() => {
    return () => {
      for (const timerId of timerRefs.current.values()) {
        window.clearTimeout(timerId);
      }
      timerRefs.current.clear();
    };
  }, []);

  const contextValue = useMemo(() => ({ addToast }), [addToast]);

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={dismissToast} registerToastElement={registerToastElement} />
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used within ToastProvider");
  }

  return context;
}

export default ToastProvider;