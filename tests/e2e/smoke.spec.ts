import { test, expect } from "@playwright/test";
test("loads the SOC workspace and docs", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Security operations")).toBeVisible();
  await page.goto("/docs");
  await expect(page.getByText("How Nexus works")).toBeVisible();
  await expect(page.getByText("API reference")).toBeVisible();
});
