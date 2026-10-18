"use client";

/**
 * The browser's own print dialog, which is also its "save as PDF". No PDF is
 * rendered here: the print stylesheet in `globals.css` already strips the
 * navigation and sets the page, so the dialog is the whole feature.
 */
export function PrintButton({ label = "print / save as PDF" }: { label?: string }) {
  return (
    <button
      type="button"
      onClick={() => window.print()}
      className="tap self-start border border-rule px-2 py-1 font-mono text-[12px] text-ink-2 hover:border-accent hover:text-accent print:hidden"
    >
      {label}
    </button>
  );
}
