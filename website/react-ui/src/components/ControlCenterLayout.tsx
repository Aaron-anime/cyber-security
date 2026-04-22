import type { ReactNode, RefObject } from "react";
import NavigationSidebar from "./NavigationSidebar";

type ControlCenterLayoutProps = {
  rootRef: RefObject<HTMLDivElement>;
  lightRayARef: RefObject<HTMLDivElement>;
  lightRayBRef: RefObject<HTMLDivElement>;
  children: ReactNode;
};

function ControlCenterLayout({
  rootRef,
  lightRayARef,
  lightRayBRef,
  children
}: ControlCenterLayoutProps) {
  return (
    <div ref={rootRef} className="control-center">
      <div ref={lightRayARef} className="light-ray-layer light-ray-layer-a" aria-hidden="true" />
      <div ref={lightRayBRef} className="light-ray-layer light-ray-layer-b" aria-hidden="true" />

      <NavigationSidebar />

      <main className="content-shell">{children}</main>
    </div>
  );
}

export default ControlCenterLayout;