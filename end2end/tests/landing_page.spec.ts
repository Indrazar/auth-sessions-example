import { test, expect } from "@playwright/test";

test("homepage has title", async ({ page }) => {
  await page.goto("https://localhost:3000/");

  await expect(page).toHaveTitle("Auth-Sessions-Example: A Letpos HTTPS Auth Example");

  await expect(page.locator("h1.big-title")).toHaveText(["Auth-Sessions-ExampleA Letpos HTTPS Auth Example"]);
});

// $env:PWDEBUG=1
// npx playwright test --debug
