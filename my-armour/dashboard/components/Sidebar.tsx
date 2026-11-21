"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Suspense, useState } from "react";

import { api } from "@/lib/api";
import { ICONS, Icon, cx, focusRing } from "./ui";

type NavItem = { href: "/" | "/live" | "/events" | "/policies" | "/playground"; label: string; icon: string };

const SECTIONS: { title: string; items: NavItem[] }[] = [
  {
    title: "Monitor",
    items: [
      { href: "/", label: "Overview", icon: ICONS.overview },
      { href: "/live", label: "Live feed", icon: ICONS.live },
      { href: "/events", label: "Events", icon: ICONS.events },
    ],
  },
  {
    title: "Configure",
    items: [
      { href: "/policies", label: "Policies", icon: ICONS.shield },
      { href: "/playground", label: "Playground", icon: ICONS.code },
    ],
  },
];

const ALL_ITEMS: NavItem[] = SECTIONS.flatMap((s) => s.items);

type IsActive = (href: string) => boolean;

/* ------------------------------------------------------------------ desktop rail */

function SideNav({ active }: { active?: IsActive }) {
  return (
    <nav aria-label="Main" className="flex flex-col">
      {SECTIONS.map((section) => (
        <div key={section.title}>
          <p className="px-3.5 pb-1.5 pt-3.5 font-display text-xs font-bold text-subtle">{section.title}</p>
          {section.items.map((item) => {
            const current = active?.(item.href) ?? false;
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={current ? "page" : undefined}
                className={cx(
                  "flex h-11 items-center gap-3 rounded-xl px-3.5 text-[14.5px] transition-colors", focusRing,
                  current ? "bg-raised font-semibold text-accent" : "font-medium text-muted hover:bg-raised/60 hover:text-fg")}
              >
                <Icon d={item.icon} />
                {item.label}
              </Link>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

/* ------------------------------------------------------------------ phone tabs */

function TabNav({ active }: { active?: IsActive }) {
  return (
    <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-4 pb-3">
      {ALL_ITEMS.map((item) => {
        const current = active?.(item.href) ?? false;
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={current ? "page" : undefined}
            className={cx(
              "flex h-9 shrink-0 items-center gap-2 rounded-full px-3.5 text-[13.5px] transition-colors", focusRing,
              current ? "bg-raised font-semibold text-accent" : "font-medium text-muted hover:text-fg")}
          >
            <Icon d={item.icon} className="h-4 w-4" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

/**
 * The only parts that read the route (for the active highlight). Kept as small
 * leaves inside <Suspense>: on routes with dynamic params (/events/[id])
 * usePathname suspends while the static shell is prerendered.
 */
function useIsActive(): IsActive {
  const pathname = usePathname();
  return (href) => (href === "/" ? pathname === "/" : pathname.startsWith(href));
}

function ActiveSideNav() {
  return <SideNav active={useIsActive()} />;
}

function ActiveTabNav() {
  return <TabNav active={useIsActive()} />;
}

/* ------------------------------------------------------------------ shell */

function SignOutButton() {
  const router = useRouter();
  const [signingOut, setSigningOut] = useState(false);

  async function signOut() {
    setSigningOut(true);
    await api.logout().catch(() => undefined);
    router.replace("/login");
    router.refresh();
  }

  return (
    <button type="button" onClick={signOut} disabled={signingOut}
      className={cx("flex h-9 items-center gap-2 rounded-full px-3 text-[13px] font-semibold text-muted",
        "transition-colors hover:bg-raised hover:text-fg disabled:opacity-50", focusRing)}>
      <Icon d={ICONS.logout} className="h-4 w-4" />
      <span className="hidden sm:inline">{signingOut ? "Signing out…" : "Sign out"}</span>
      <span className="sr-only sm:hidden">Sign out</span>
    </button>
  );
}

export function Wordmark({ size = "md" }: { size?: "md" | "lg" }) {
  return (
    <span className="flex items-center gap-2.5">
      <span className={cx("grid place-items-center rounded-full bg-elevated text-accent",
        size === "lg" ? "h-12 w-12" : "h-8 w-8")}>
        <Icon d={ICONS.shield} className={size === "lg" ? "h-6 w-6" : "h-[18px] w-[18px]"} />
      </span>
      <span className={cx("font-display font-bold tracking-[-0.2px] text-fg", size === "lg" ? "text-[26px]" : "text-[20px]")}>
        Proxy Armour
      </span>
    </span>
  );
}

export function AppHeader() {
  return (
    <header className="sticky top-0 z-30 bg-canvas/95 backdrop-blur">
      <div className="flex h-16 items-center gap-3.5 px-4 sm:px-6">
        <Link href="/" className={cx("rounded-full", focusRing)} aria-label="Proxy Armour overview">
          <Wordmark />
        </Link>
        <span className="hidden text-[15px] font-semibold text-muted sm:inline">Admin</span>
        <span className="flex-1" />
        <SignOutButton />
        <span aria-hidden="true"
          className="grid h-9 w-9 place-items-center rounded-full bg-elevated text-sm font-semibold text-fg">
          A
        </span>
      </div>
      <div className="md:hidden">
        <Suspense fallback={<TabNav />}>
          <ActiveTabNav />
        </Suspense>
      </div>
    </header>
  );
}

export function Sidebar() {
  return (
    <aside className="sticky top-16 hidden h-[calc(100vh-4rem)] w-[248px] shrink-0 flex-col px-3 pb-6 pt-2 md:flex">
      <Suspense fallback={<SideNav />}>
        <ActiveSideNav />
      </Suspense>
      <div className="mt-auto rounded-2xl bg-surface p-4">
        <p className="flex items-center gap-2 text-[13px] font-semibold text-fg">
          <Icon d={ICONS.shield} className="h-4 w-4 text-accent" />
          Metadata only
        </p>
        <p className="mt-1 text-[12.5px] leading-relaxed text-subtle">
          Prompts, original values and placeholders are never stored or shown here.
        </p>
      </div>
    </aside>
  );
}
