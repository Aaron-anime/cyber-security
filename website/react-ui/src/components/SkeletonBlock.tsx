type SkeletonBlockProps = {
  className?: string;
};

function SkeletonBlock({ className = "" }: SkeletonBlockProps) {
  return <span className={`skeleton-block ${className}`.trim()} aria-hidden="true" />;
}

export default SkeletonBlock;