import { test, expect } from "@playwright/test";

test("primary pages expose named landmarks and headings", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("main")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Security operations" })).toBeVisible();
  await page.goto("/docs");
  await expect(page.getByRole("heading", { name: "How every control works" })).toBeVisible();
  await expect(page.getByRole("link", { name: /Back to Nexus/ })).toBeVisible();
});
