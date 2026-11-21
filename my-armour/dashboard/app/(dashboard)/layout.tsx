import { AppHeader, Sidebar } from "@/components/Sidebar";

export default function DashboardLayout({ children }: LayoutProps<"/">) {
  return (
    <div className="min-h-screen">
      <AppHeader />
      <div className="flex">
        <Sidebar />
        <main className="min-w-0 flex-1 px-4 pb-16 pt-4 sm:px-6 md:pt-6 lg:px-10">
          <div className="max-w-[1120px]">{children}</div>
        </main>
      </div>
    </div>
  );
}
