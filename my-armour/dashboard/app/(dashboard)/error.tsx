"use client";

import { ErrorState, PageHeader } from "@/components/ui";

export default function DashboardError({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <>
      <PageHeader title="Something went wrong" />
      <ErrorState message={error.message || "Unexpected error while rendering this page."} onRetry={reset} />
    </>
  );
}
