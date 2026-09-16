/* Inline SVG icons for the sidebar and brand.
 *
 * Inline rather than an icon package: this console is embedded in the server
 * binary, and the whole set here is smaller than the dependency would be.
 *
 * Every icon is aria-hidden. The nav link's text is its accessible name, and
 * an icon that announced itself would make each item read twice to a screen
 * reader — and would break the E2E tests, which select links by name.
 */

type IconProps = { className?: string };

function svg(path: React.ReactNode, className = "nav-icon") {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {path}
    </svg>
  );
}

/* The FreeLocker mark: a shield (this is endpoint protection) with a keyhole
   (this is about what may run). Ours, not borrowed. */
export function BrandMark({ className = "brand-mark" }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M12 2.2 4.6 5.1v6.3c0 4.6 3.1 8.8 7.4 10.4 4.3-1.6 7.4-5.8 7.4-10.4V5.1L12 2.2Z"
        fill="currentColor"
        opacity="0.16"
      />
      <path
        d="M12 2.2 4.6 5.1v6.3c0 4.6 3.1 8.8 7.4 10.4 4.3-1.6 7.4-5.8 7.4-10.4V5.1L12 2.2Z"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.7}
        strokeLinejoin="round"
      />
      <circle cx="12" cy="10.4" r="2.05" fill="currentColor" />
      <path d="M12 12.1v3.5" stroke="currentColor" strokeWidth={1.9} strokeLinecap="round" />
    </svg>
  );
}

export const IconDevices = (p: IconProps) =>
  svg(
    <>
      <rect x="2.5" y="4.5" width="14" height="10" rx="1.6" />
      <path d="M6 18.5h7" />
      <path d="M19 9.5h2.5v9H19z" />
    </>,
    p.className
  );

export const IconPolicies = (p: IconProps) =>
  svg(
    <>
      <path d="M6 3.5h8l4.5 4.5v12.5H6z" />
      <path d="M14 3.5V8h4.5" />
      <path d="M9 13h6M9 16.5h4" />
    </>,
    p.className
  );

export const IconRingfence = (p: IconProps) =>
  svg(
    <>
      <circle cx="12" cy="12" r="3.2" />
      <path d="M12 3.2v2.4M12 18.4v2.4M3.2 12h2.4M18.4 12h2.4" />
      <path d="M5.8 5.8 7.5 7.5M16.5 16.5l1.7 1.7M18.2 5.8 16.5 7.5M7.5 16.5l-1.7 1.7" />
    </>,
    p.className
  );

export const IconBlocked = (p: IconProps) =>
  svg(
    <>
      <circle cx="12" cy="12" r="8.6" />
      <path d="M6 6l12 12" />
    </>,
    p.className
  );

export const IconApprovals = (p: IconProps) =>
  svg(
    <>
      <path d="M20.5 11.2V12a8.5 8.5 0 1 1-5-7.8" />
      <path d="M9 11.5l3 3 8.5-8.5" />
    </>,
    p.className
  );

export const IconAlerts = (p: IconProps) =>
  svg(
    <>
      <path d="M12 3.2a5.6 5.6 0 0 0-5.6 5.6c0 5-2.2 6.5-2.2 6.5h15.6s-2.2-1.5-2.2-6.5A5.6 5.6 0 0 0 12 3.2Z" />
      <path d="M10.3 19a2 2 0 0 0 3.4 0" />
    </>,
    p.className
  );

export const IconNotifications = (p: IconProps) =>
  svg(
    <>
      <rect x="2.8" y="5" width="18.4" height="14" rx="2" />
      <path d="m3.5 6.5 8.5 6.2 8.5-6.2" />
    </>,
    p.className
  );

export const IconActivity = (p: IconProps) =>
  svg(<path d="M2.8 12.5h4l2.4-6.6 3.8 12 2.6-8 1.9 2.6h3.7" />, p.className);

export const IconTokens = (p: IconProps) =>
  svg(
    <>
      <circle cx="8" cy="12" r="3.6" />
      <path d="M11.6 12h9.6M18 12v3.2M15 12v2.2" />
    </>,
    p.className
  );

export const IconGroups = (p: IconProps) =>
  svg(
    <>
      <circle cx="9" cy="8.6" r="3.1" />
      <path d="M3.2 19.2c0-3.1 2.6-5.1 5.8-5.1s5.8 2 5.8 5.1" />
      <path d="M16.2 6.2a3 3 0 0 1 0 5.6M17.6 14.6c2 .6 3.4 2.2 3.4 4.6" />
    </>,
    p.className
  );

export const IconAdmins = (p: IconProps) =>
  svg(
    <>
      <circle cx="12" cy="8" r="3.4" />
      <path d="M5.5 20c0-3.4 2.9-5.6 6.5-5.6s6.5 2.2 6.5 5.6" />
    </>,
    p.className
  );

export const IconReleases = (p: IconProps) =>
  svg(
    <>
      <path d="M12 3.2v11" />
      <path d="m7.8 10.2 4.2 4.2 4.2-4.2" />
      <path d="M4.5 17.5v1.8a1.5 1.5 0 0 0 1.5 1.5h12a1.5 1.5 0 0 0 1.5-1.5v-1.8" />
    </>,
    p.className
  );

export const IconAudit = (p: IconProps) =>
  svg(
    <>
      <circle cx="11" cy="11" r="6.6" />
      <path d="m16 16 4.6 4.6" />
      <path d="M11 8v3.2l2 1.2" />
    </>,
    p.className
  );

export const IconTenants = (p: IconProps) =>
  svg(
    <>
      <path d="M3.5 20.5V6.2l7-3v17.3" />
      <path d="M10.5 9.5h9.5v11h-9.5" />
      <path d="M14 13h2.5M14 16.5h2.5M6.5 9.5h1M6.5 13h1" />
    </>,
    p.className
  );
