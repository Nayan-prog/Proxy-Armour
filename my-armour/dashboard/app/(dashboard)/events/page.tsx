import type { Metadata } from "next";
import { Suspense } from "react";

import { LoadingBlock, PageHeader } from "@/components/ui";
import { EventsView } from "./EventsView";

export const metadata: Metadata = { title: "Events" };

export default function EventsPage() {
  return (
    <>
      <PageHeader title="Events"
        description="One row per proxied LLM request. Metadata only - no prompts, values or placeholders." />
      <Suspense fallback={<LoadingBlock />}>
        <EventsView />
      </Suspense>
    </>
  );
}
