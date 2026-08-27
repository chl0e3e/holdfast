import assert from "node:assert/strict";
import { isSafeHttpLink } from "./links.js";

assert.equal(isSafeHttpLink("https://example.com/path"), true);
assert.equal(isSafeHttpLink("http://127.0.0.1:8080/"), true);
assert.equal(isSafeHttpLink("javascript:alert(1)"), false);
assert.equal(isSafeHttpLink("file:///etc/passwd"), false);
assert.equal(isSafeHttpLink("not a url"), false);

console.log("desktop link tests passed");
