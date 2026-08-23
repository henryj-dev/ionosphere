/** 자동설정 조립 배선 — IonosphereApp이 autoconfigPort로 리슨하고 hostname/993/465를 광고. */
import { afterAll, beforeAll, describe, expect, test } from "@ionosphere/testkit";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IonosphereApp } from "../src/app.ts";
import { E2E_HOOK_TIMEOUT_MS, offlineResolver } from "./helpers.ts";

describe("autoconfig 조립 배선", () => {
  let app: IonosphereApp;
  let blobRoot: string;

  beforeAll(async () => {
    blobRoot = mkdtempSync(join(tmpdir(), "ionosphere-ac-"));
    app = new IonosphereApp({
      hostname: "mx.test.local",
      dbPath: ":memory:",
      blobRoot,
      smtpPort: 0,
      pop3Port: 0,
      autoconfigPort: 0, // 임의 포트
      autoconfigBrand: "TestMail",
      resolver: offlineResolver(),
    });
    await app.start();
  }, E2E_HOOK_TIMEOUT_MS);

  afterAll(async () => {
    await app.stop();
    rmSync(blobRoot, { recursive: true, force: true });
  }, E2E_HOOK_TIMEOUT_MS);

  test("Thunderbird 엔드포인트가 hostname과 표준 TLS 포트를 광고", async () => {
    const res = await fetch(`http://127.0.0.1:${app.autoconfigPort}/mail/config-v1.1.xml?emailaddress=u@test.local`);
    expect(res.status).toBe(200);
    const xml = await res.text();
    expect(xml).toContain("<hostname>mx.test.local</hostname>");
    expect(xml).toContain("<port>993</port>");
    expect(xml).toContain("<port>465</port>");
    expect(xml).toContain("<displayShortName>TestMail</displayShortName>");
  });

  test("Apple mobileconfig 엔드포인트 응답", async () => {
    const res = await fetch(`http://127.0.0.1:${app.autoconfigPort}/email.mobileconfig?email=u@test.local`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("apple-aspen-config");
  });
});
