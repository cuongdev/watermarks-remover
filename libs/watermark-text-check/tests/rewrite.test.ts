import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildPrompt,
  callOllama,
  checkRemote,
  lexicalDivergence,
  rewriteText,
  selectCandidate,
} from "../src/index.js";

test("buildPrompt embeds the text for each strength", () => {
  const p = buildPrompt("paraphrase", "SOURCE TEXT");
  assert.ok(p.includes("SOURCE TEXT"));
  assert.ok(p.includes("substantially different wording"));

  const bt = buildPrompt("backtranslate", "SOURCE", { lang: "German" });
  assert.ok(bt.includes("German"));
  assert.ok(bt.includes("English"));

  assert.throws(() => buildPrompt("nope" as never, "x"), /unknown strength/);
});

test("print-prompt backend returns the prompt without a model", async () => {
  const { text, info } = await rewriteText("hello world", {});
  assert.equal(info.mode, "print-prompt");
  assert.ok(text.includes("hello world"));
});

test("checkRemote enforces loopback default deny", () => {
  checkRemote("http://127.0.0.1:11434", false); // ok
  checkRemote("http://localhost:8080", false); // ok
  assert.throws(() => checkRemote("https://api.example.com", false), /not loopback/);
  checkRemote("https://api.example.com", true); // opt-in ok
  assert.throws(() => checkRemote("file:///etc/passwd", true), /must be http/);
});

test("lexicalDivergence and candidate selection", () => {
  assert.equal(lexicalDivergence("same words here", "same words here"), 0);
  assert.ok(lexicalDivergence("alpha beta gamma", "delta epsilon zeta") > 0.9);

  const original = "the quick brown fox jumps over the lazy dog";
  const near = "the quick brown fox jumps over a lazy dog";
  const far = "a speedy russet fox leapt across one sleepy hound";
  const { best, scores } = selectCandidate(original, [near, far]);
  assert.equal(best, far);
  assert.equal(scores.length, 2);
});

test("ollama backend via injected fetch, with Layer A scrub after", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fakeFetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init: init! });
    return new Response(
      // model output smuggles a zero width space; layerAAfter must remove it
      JSON.stringify({ message: { content: "re\u200Bwritten output" } }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as typeof fetch;

  const { text, info } = await rewriteText("original input", {
    backend: "ollama",
    model: "llama3.2",
    baseUrl: "http://127.0.0.1:11434",
    fetchImpl: fakeFetch,
  });
  assert.equal(text, "rewritten output");
  assert.equal(info.mode, "rewritten");
  assert.equal((info.layerAAfter as { removedCount: number }).removedCount, 1);
  assert.equal(calls.length, 1);
  assert.ok(calls[0]!.url.endsWith("/api/chat"));
  assert.equal(calls[0]!.init.redirect, "error");
});

test("openai-compatible backend sends bearer key and parses choices", async () => {
  let authHeader: string | undefined;
  const fakeFetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
    authHeader = (init!.headers as Record<string, string>)["Authorization"];
    return new Response(
      JSON.stringify({ choices: [{ message: { content: "out" } }] }),
      { status: 200 },
    );
  }) as typeof fetch;

  const { text } = await rewriteText("input", {
    backend: "openai-compatible",
    model: "m",
    baseUrl: "http://localhost:8000",
    apiKey: "sk-test",
    layerAAfter: false,
    fetchImpl: fakeFetch,
  });
  assert.equal(text, "out");
  assert.equal(authHeader, "Bearer sk-test");
});

test("remote endpoint is refused before any request is made", async () => {
  let called = false;
  const fakeFetch = (async () => {
    called = true;
    return new Response("{}");
  }) as typeof fetch;
  await assert.rejects(
    rewriteText("x", {
      backend: "ollama",
      model: "m",
      baseUrl: "https://evil.example.com",
      fetchImpl: fakeFetch,
    }),
    /not loopback/,
  );
  assert.equal(called, false);
});

test("candidate scoring picks the most diverged model output", async () => {
  const outputs = [
    "the quick brown fox jumps over the lazy dog",
    "a speedy russet fox leapt across one sleepy hound",
  ];
  let call = 0;
  const fakeFetch = (async () => {
    const content = outputs[call];
    call += 1;
    return new Response(JSON.stringify({ message: { content } }), { status: 200 });
  }) as typeof fetch;

  const { text, info } = await rewriteText("the quick brown fox jumps over the lazy dog", {
    backend: "ollama",
    model: "m",
    baseUrl: "http://127.0.0.1:11434",
    candidates: 2,
    layerAAfter: false,
    fetchImpl: fakeFetch,
  });
  assert.equal(text, outputs[1]);
  assert.equal(info.candidates, 2);
  assert.equal(info.candidateScores?.length, 2);
});

test("callOllama surfaces empty responses as errors", async () => {
  const fakeFetch = (async () =>
    new Response(JSON.stringify({ message: {} }), { status: 200 })) as typeof fetch;
  await assert.rejects(
    callOllama("http://127.0.0.1:11434", "m", "p", { fetchImpl: fakeFetch }),
    /empty response/,
  );
});
