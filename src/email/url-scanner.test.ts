// Required Notice: Copyright Regun Software SRL (https://carapa.ai)

import { expect, test, describe } from "bun:test";
import { analyzeUrl, extractUrls, injectUrlWarnings, getLevenshteinDistance, calculateEntropy } from "./url-scanner.js";

describe("URL Scanner", () => {
  test("extracts multiple URLs", () => {
    const text = "Check https://google.com and http://example.org/path?q=1";
    const urls = extractUrls(text);
    expect(urls).toContain("https://google.com");
    expect(urls).toContain("http://example.org/path?q=1");
  });

  test("identifies typosquatting", () => {
    const analysis = analyzeUrl("https://g00gle.com");
    expect(analysis.riskScore).toBeGreaterThan(0.5);
    expect(analysis.risks.some(r => r.includes("typosquatting"))).toBe(true);
  });

  test("identifies high entropy domains", () => {
    const analysis = analyzeUrl("https://ajhfgakshjgf-random.ru");
    expect(analysis.risks).toContain("High domain entropy (potential DGA or random domain)");
  });

  test("whitelists safe domains", () => {
    const analysis = analyzeUrl("https://google.com");
    expect(analysis.riskScore).toBe(0);
    expect(analysis.risks.length).toBe(0);
  });

  test("identifies IP hostnames", () => {
    const analysis = analyzeUrl("http://192.168.1.1/login");
    expect(analysis.risks).toContain("IP address used as hostname");
  });

  test("identifies suspicious TLDs", () => {
    const analysis = analyzeUrl("https://invoice.zip");
    expect(analysis.risks).toContain("Suspicious TLD");
  });

  test("identifies Punycode (homograph)", () => {
    const analysis = analyzeUrl("https://xn--80ak6aa92e.com"); // apple.com in punycode (approx)
    expect(analysis.risks).toContain("Punycode domain (potential homograph attack)");
  });

  test("identifies URL shorteners", () => {
    const analysis = analyzeUrl("https://bit.ly/abc123");
    expect(analysis.risks).toContain("URL shortener (obscures final destination)");
  });

  test("handles invalid URLs gracefully", () => {
    const analysis = analyzeUrl("not-a-url");
    expect(analysis.domain).toBe("invalid");
  });

  test("detects multiple subdomains", () => {
    const analysis = analyzeUrl("https://a.b.c.d.e.evil.com");
    expect(analysis.risks).toContain("High number of subdomains");
  });

  test("removes trailing punctuation from extracted URLs", () => {
    const urls = extractUrls("Visit https://example.com, or https://test.org.");
    expect(urls).toContain("https://example.com");
    expect(urls).toContain("https://test.org");
  });

  test("deduplicates extracted URLs", () => {
    const urls = extractUrls("https://example.com and https://example.com again");
    expect(urls.filter(u => u === "https://example.com")).toHaveLength(1);
  });
});

describe("Levenshtein Distance", () => {
  test("identical strings have distance 0", () => {
    expect(getLevenshteinDistance("abc", "abc")).toBe(0);
  });

  test("single character difference", () => {
    expect(getLevenshteinDistance("cat", "bat")).toBe(1);
  });

  test("empty strings", () => {
    expect(getLevenshteinDistance("", "")).toBe(0);
    expect(getLevenshteinDistance("abc", "")).toBe(3);
    expect(getLevenshteinDistance("", "abc")).toBe(3);
  });
});

describe("Entropy", () => {
  test("single repeated character has zero entropy", () => {
    expect(calculateEntropy("aaaa")).toBe(0);
  });

  test("high variety string has higher entropy", () => {
    const low = calculateEntropy("aaa");
    const high = calculateEntropy("abcdef");
    expect(high).toBeGreaterThan(low);
  });
});

describe("Link Defanging", () => {
  test("plain text: defangs unsafe URLs with hxxps:// and [.]", () => {
    const result = injectUrlWarnings("Click here: https://g00gle.com/login", false);
    expect(result).toContain("hxxps://");
    expect(result).toContain("g00gle[.]com");
    expect(result).toContain("UNSAFE");
    // Original URL should no longer be present
    expect(result).not.toContain("https://g00gle.com");
  });

  test("plain text: safe URLs are not defanged", () => {
    const result = injectUrlWarnings("Visit https://google.com", false);
    expect(result).toContain("https://google.com");
    expect(result).not.toContain("hxxps://");
    expect(result).not.toContain("[.]");
  });

  test("HTML: rewrites href to #blocked for unsafe URLs", () => {
    const html = '<a href="https://g00gle.com/login">Click here</a>';
    const result = injectUrlWarnings(html, true);
    expect(result).toContain('href="#blocked"');
    expect(result).toContain('data-original-url');
    expect(result).not.toContain('href="https://g00gle.com/login"');
  });

  test("HTML: injects BLOCKED warning badge for unsafe URLs", () => {
    const html = '<p>Visit https://g00gle.com/login</p>';
    const result = injectUrlWarnings(html, true);
    expect(result).toContain("BLOCKED");
    expect(result).toContain("color:red");
  });

  test("HTML: safe URLs are not modified", () => {
    const html = '<a href="https://google.com">Google</a>';
    const result = injectUrlWarnings(html, true);
    expect(result).toContain('href="https://google.com"');
    expect(result).not.toContain("#blocked");
  });

  test("handles text with no URLs", () => {
    const result = injectUrlWarnings("No URLs here.", false);
    expect(result).toBe("No URLs here.");
  });
});
