import type { Metadata } from "next";
import { Suspense } from "react";

import { LoadingBlock, PageHeader } from "@/components/ui";
import { EventDetail } from "./EventDetail";

export const metadata: Metadata = { title: "Event" };

/**
 * Server shell. `params` is request data, so it is unwrapped inside <Suspense>
 * (Cache Components: the rest of the page is prerendered as a static shell).
 */
export default function EventDetailPage({ params }: PageProps<"/events/[id]">) {
  return (
    <Suspense fallback={<><PageHeader title="Event" /><LoadingBlock /></>}>
      <EventDetail params={params} />
    </Suspense>
  );
}
