import assert from "node:assert/strict";
import { DOCKERWM_DEFAULT, dockerwmOpenUrl, isSafeHttpLink } from "./links.js";

assert.equal(isSafeHttpLink("https://example.com/path"), true);
assert.equal(isSafeHttpLink("http://127.0.0.1:8080/"), true);
assert.equal(isSafeHttpLink("javascript:alert(1)"), false);
assert.equal(isSafeHttpLink("file:///etc/passwd"), false);
assert.equal(isSafeHttpLink("not a url"), false);
assert.equal(
  dockerwmOpenUrl("https://docker.example/", "https://a.b/c?d=e&f=g"),
  "https://docker.example/?url=https%3A%2F%2Fa.b%2Fc%3Fd%3De%26f%3Dg",
);
assert.equal(DOCKERWM_DEFAULT, "https://docker.direct.asylum.st");

console.log("desktop link tests passed");
