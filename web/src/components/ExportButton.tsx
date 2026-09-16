// ExportButton downloads a CSV export of the current page's feed.
//
// A plain anchor rather than a fetch: the server sends the file with
// Content-Disposition: attachment, so the browser saves it directly and
// never holds the whole export in JS memory. The session cookie rides along
// on a same-origin navigation, and no CSRF token is needed because the
// export is a GET with no side effects beyond its audit record.
export function ExportButton({ resource, label = "Export CSV" }: { resource: string; label?: string }) {
  return (
    <a className="button ghost" href={`/api/exports/${resource}.csv`} download>
      {label}
    </a>
  );
}
