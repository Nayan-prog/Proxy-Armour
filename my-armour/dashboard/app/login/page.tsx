import type { Metadata } from "next";
import { Suspense } from "react";

import { Wordmark } from "@/components/Sidebar";
import { LoginForm } from "./LoginForm";

export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  return (
    <main className="flex min-h-screen justify-center px-5 py-16 sm:py-[72px]">
      <div className="w-full max-w-[440px]">
        <Wordmark />
        <h1 className="mb-2 mt-12 text-[34px] font-bold leading-10 tracking-[-0.5px] text-fg">Sign in</h1>
        <p className="mb-8 text-[15px] leading-[21px] text-muted">to the Proxy Armour admin console</p>
        <Suspense fallback={<div className="h-64 animate-pulse rounded-2xl bg-surface" />}>
          <LoginForm />
        </Suspense>
      </div>
    </main>
  );
}
