import { useRef } from "react";
import gsap from "gsap";
import { useGSAP } from "@gsap/react";

gsap.registerPlugin(useGSAP);

export function useGsapAnimations() {
  const containerRef = useRef<HTMLDivElement | null>(null);

  useGSAP(
    () => {
      const panels = gsap.utils.toArray<HTMLElement>(".panel-reveal");

      gsap.fromTo(
        ".light-ray-layer-a",
        { xPercent: -3, opacity: 0.2 },
        {
          xPercent: 3,
          opacity: 0.45,
          duration: 9,
          repeat: -1,
          yoyo: true,
          ease: "sine.inOut"
        }
      );

      gsap.fromTo(
        ".light-ray-layer-b",
        { yPercent: 0, opacity: 0.3 },
        {
          yPercent: -5,
          opacity: 0.5,
          duration: 7,
          repeat: -1,
          yoyo: true,
          ease: "sine.inOut"
        }
      );

      gsap.fromTo(
        panels,
        { y: 26, autoAlpha: 0 },
        {
          y: 0,
          autoAlpha: 1,
          duration: 0.7,
          stagger: 0.08,
          ease: "power2.out",
          clearProps: "transform"
        }
      );
    },
    { scope: containerRef }
  );

  return { containerRef };
}