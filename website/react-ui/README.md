# React Refactor Phase 1

This folder is the initial React + TypeScript + GSAP refactor of the Cyber Security Control Center UI.

## Included Components

- `NavigationSidebar`
- `MainDashboard`
- `ToolLibraryGrid`

## Animation Migration

- CSS keyframe-style behavior has been moved to GSAP hooks in `src/hooks/useGsapAnimations.ts`.
- Background light rays use continuous GSAP tween loops.
- Dashboard/panel reveal animations use staggered GSAP entrance tweens.

## Run Locally

1. Open a terminal in `website/react-ui`
2. Install dependencies:

```bash
npm install
```

3. Start dev server:

```bash
npm run dev
```

4. Build for production:

```bash
npm run build
```