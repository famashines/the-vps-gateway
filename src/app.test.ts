import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import Fastify from "fastify";
import * as oidc from "openid-client";
import { buildApp, LOGIN_COOKIE, SESSION_COOKIE, type Session } from "./app.ts";
import { sealer } from "./seal.ts";

const sessionKey = randomBytes(32).toString("base64");
const appUrl = "https://dev.app.test";
const idp = new oidc.Configuration(
  {
    issuer: "https://idp.test/realms/the-vps",
    authorization_endpoint: "https://idp.test/realms/the-vps/auth",
    token_endpoint: "https://idp.test/realms/the-vps/token",
    end_session_endpoint: "https://idp.test/realms/the-vps/logout",
  },
  "the-vps-bff",
  "secret",
);
const received: Array<Record<string, any>> = [];
const fakeAdmissions = Fastify();
fakeAdmissions.get("/students", async () => [{ studentId: "s1" }]);
fakeAdmissions.get("/academic-years", async () => [{ academicYearId: "y1", name: "2026-27", classes: [] }]);
for (const path of ["open-academic-year", "open-class", "close-class", "enroll-student", "update-student-details", "change-student-class", "update-academic-year", "mark-student-left", "cancel-student-leaving"]) {
  fakeAdmissions.post(`/commands/${path}`, async (request, reply) => {
    received.push({ path, ...(request.body as Record<string, any>) });
    return reply.code(201).send({ ok: path });
  });
}
fakeAdmissions.post("/commands/register-student", async (request, reply) => {
  received.push(request.body as Record<string, any>);
  return reply.code(201).send({ studentId: "s2", admissionNumber: "2026-0001" });
});
const fakeFees = Fastify();
fakeFees.get("/accounts", async () => [{ accountId: "a1" }]);
fakeFees.get("/fee-schedules", async () => [{ grade: "class-3" }]);
fakeFees.get("/accounts/:id", async (request) => ({ accountId: (request.params as { id: string }).id }));
for (const path of ["set-fee-schedule", "receive-payment", "reverse-charge", "reverse-payment"]) {
  fakeFees.post(`/commands/${path}`, async (request, reply) => {
    received.push({ path, ...(request.body as Record<string, any>) });
    return reply.code(201).send({ ok: path });
  });
}
let admissionsUrl = "";
let feesUrl = "";
before(async () => {
  admissionsUrl = await fakeAdmissions.listen({ host: "127.0.0.1", port: 0 });
  feesUrl = await fakeFees.listen({ host: "127.0.0.1", port: 0 });
});
after(() => Promise.all([fakeAdmissions.close(), fakeFees.close()]));

const app = (overrides: { admissionsUrl?: string; feesUrl?: string } = {}) =>
  buildApp({
    appUrl,
    issuer: "https://idp.test/realms/the-vps",
    clientId: "the-vps-bff",
    clientSecret: "secret",
    sessionKey,
    admissionsUrl: overrides.admissionsUrl ?? admissionsUrl,
    feesUrl: overrides.feesUrl ?? feesUrl,
    oidcConfig: async () => idp,
  });

const sessionCookie = (roles: string[], exp = Math.floor(Date.now() / 1000) + 600) => {
  const session: Session = { sub: "u1", name: "Ayesha Khan", roles, idToken: "id.token.value", exp };
  return { [SESSION_COOKIE]: sealer(sessionKey).seal(session) };
};

test("health is public and shows the release", async () => {
  process.env.RELEASE = "abc1234";
  const response = await app().inject({ url: "/api/health" });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { status: "ok", release: "abc1234" });
});

test("me without a session gives 401", async () => {
  const response = await app().inject({ url: "/api/me" });
  assert.equal(response.statusCode, 401);
});

test("me with a session gives the name and roles, not the token", async () => {
  const response = await app().inject({ url: "/api/me", cookies: sessionCookie(["admin"]) });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { sub: "u1", name: "Ayesha Khan", roles: ["admin"] });
});

test("an expired or changed session is no session", async () => {
  const expired = await app().inject({ url: "/api/me", cookies: sessionCookie(["admin"], 1) });
  assert.equal(expired.statusCode, 401);
  const valid = sessionCookie(["admin"])[SESSION_COOKIE];
  const changed = valid.slice(0, -2) + (valid.endsWith("A") ? "B" : "A") + valid.slice(-1);
  const tampered = await app().inject({ url: "/api/me", cookies: { [SESSION_COOKIE]: changed } });
  assert.equal(tampered.statusCode, 401);
});

test("the admin API: 401 without a session, 403 for a student, 200 for an admin", async () => {
  assert.equal((await app().inject({ url: "/api/students" })).statusCode, 401);
  assert.equal((await app().inject({ url: "/api/students", cookies: sessionCookie(["student"]) })).statusCode, 403);
  const admin = await app().inject({ url: "/api/students", cookies: sessionCookie(["admin"]) });
  assert.equal(admin.statusCode, 200);
  assert.deepEqual(admin.json(), [{ studentId: "s1" }]);
});

test("login redirects to Keycloak with PKCE and sets a short login cookie", async () => {
  const response = await app().inject({ url: "/api/auth/login?returnTo=/students" });
  assert.equal(response.statusCode, 302);
  const location = new URL(response.headers.location as string);
  assert.equal(location.origin + location.pathname, "https://idp.test/realms/the-vps/auth");
  assert.equal(location.searchParams.get("redirect_uri"), `${appUrl}/api/auth/callback`);
  assert.equal(location.searchParams.get("code_challenge_method"), "S256");
  assert.ok(location.searchParams.get("state") && location.searchParams.get("nonce"));
  const login = response.cookies.find((c) => c.name === LOGIN_COOKIE)!;
  assert.equal(login.httpOnly, true);
  assert.equal(login.secure, true);
  assert.equal(login.sameSite, "Lax");
  assert.equal(login.maxAge, 600);
});

test("login keeps only a local returnTo", async () => {
  for (const returnTo of ["https://evil.test/", "//evil.test", "/\\evil.test"]) {
    const response = await app().inject({ url: `/api/auth/login?returnTo=${encodeURIComponent(returnTo)}` });
    const login = sealer(sessionKey).open<{ returnTo: string }>(response.cookies.find((c) => c.name === LOGIN_COOKIE)!.value);
    assert.equal(login?.returnTo, "/");
  }
});

test("a callback without a login cookie fails safely", async () => {
  const response = await app().inject({ url: "/api/auth/callback?code=x&state=y" });
  assert.equal(response.statusCode, 302);
  assert.equal(response.headers.location, "/?signin=failed");
});

test("logout: other origins are refused; our origin clears the session and ends the Keycloak session", async () => {
  const foreign = await app().inject({ method: "POST", url: "/api/auth/logout", headers: { origin: "https://evil.test" }, cookies: sessionCookie(["admin"]) });
  assert.equal(foreign.statusCode, 403);
  const response = await app().inject({ method: "POST", url: "/api/auth/logout", headers: { origin: appUrl }, cookies: sessionCookie(["admin"]) });
  assert.equal(response.statusCode, 200);
  const redirect = new URL(response.json().redirect);
  assert.equal(redirect.origin + redirect.pathname, "https://idp.test/realms/the-vps/logout");
  assert.equal(redirect.searchParams.get("id_token_hint"), "id.token.value");
  assert.equal(redirect.searchParams.get("post_logout_redirect_uri"), `${appUrl}/`);
  const cleared = response.cookies.find((c) => c.name === SESSION_COOKIE)!;
  assert.equal(cleared.value, "");
});

const student = {
  firstName: "Ayesha",
  lastName: "Khan",
  fatherName: "Imran Khan",
  dateOfBirth: "2016-03-14",
  gender: "female",
  guardian: { name: "Imran Khan", relation: "father", phone: "+923001234567", cnic: "35202-7654321-9" },
  bFormNumber: "35202-1234567-8",
  address: "House 12, Street 4, Gulberg III, Lahore",
  familyStatus: "father-deceased",
  familyStatusNote: "The uncle pays the fees.",
  siblings: { count: 1, studentIds: [] },
};
const key = "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f";
const register = (body: unknown, headers: Record<string, string> = { "idempotency-key": key }, roles = ["admin"], instance = app()) =>
  instance.inject({ method: "POST", url: "/api/students", headers: { origin: appUrl, ...headers }, cookies: sessionCookie(roles), payload: body as object });

test("register: an admin's valid student goes to admissions as a command envelope", async () => {
  received.length = 0;
  const response = await register(student);
  assert.equal(response.statusCode, 201);
  assert.deepEqual(response.json(), { studentId: "s2", admissionNumber: "2026-0001" });
  const command = received[0];
  assert.equal(command.commandId, key);
  assert.equal(command.commandType, "admissions.RegisterStudent");
  assert.equal(command.version, 1);
  assert.equal(command.issuedBy, "u1");
  assert.deepEqual(command.payload, student);
});

test("register: a student user gets 403 and nothing reaches admissions", async () => {
  received.length = 0;
  assert.equal((await register(student, undefined, ["student"])).statusCode, 403);
  assert.equal(received.length, 0);
});

test("register: wrong fields come back by name, and nothing reaches admissions", async () => {
  received.length = 0;
  const response = await register({
    ...student,
    dateOfBirth: "2016-02-30",
    guardian: { name: "Imran Khan", relation: "father" },
    grade: "3",
    bFormNumber: "3520212345678",
    familyStatus: "orphan",
    siblings: { count: -1, studentIds: [] },
  });
  assert.equal(response.statusCode, 400);
  const fields = response.json().fields.map((f: { field: string }) => f.field).sort();
  assert.deepEqual(fields, ["bFormNumber", "dateOfBirth", "familyStatus", "grade", "guardian.cnic", "guardian.phone", "siblings.count"]);
  assert.equal(received.length, 0);
});

test("register: the Idempotency-Key must be a UUID", async () => {
  assert.equal((await register(student, {})).statusCode, 400);
  assert.equal((await register(student, { "idempotency-key": "1" })).statusCode, 400);
});

test("register: a foreign origin is refused", async () => {
  assert.equal((await register(student, { "idempotency-key": key, origin: "https://evil.test" })).statusCode, 403);
});

test("register: admissions down gives 502 with a clear message", async () => {
  const response = await register(student, undefined, ["admin"], app({ admissionsUrl: "http://127.0.0.1:9" }));
  assert.equal(response.statusCode, 502);
  assert.match(response.json().error, /did not answer/);
});

const post = (url: string, body: object, roles = ["admin"]) =>
  app().inject({ method: "POST", url, headers: { origin: appUrl, "idempotency-key": key }, cookies: sessionCookie(roles), payload: body });

test("enrollment routes: each command goes to its admissions path with its type", async () => {
  received.length = 0;
  const year = { name: "2026-27", startsOn: "2026-04-01", endsOn: "2027-03-31" };
  const opened = { academicYearId: "5b1f0e2a-3c4d-4e5f-8a6b-7c8d9e0f1a2b", grade: "kg-1" };
  const enroll = { studentId: "0b8e6f3a-6a2e-4f7e-9a51-2f1d3c4b5a69", classId: "9c8b7a6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d" };
  assert.equal((await post("/api/academic-years", year)).statusCode, 201);
  assert.equal((await post("/api/classes", opened)).statusCode, 201);
  assert.equal((await post("/api/enrollments", enroll)).statusCode, 201);
  assert.equal((await post(`/api/classes/${enroll.classId}/closure`, { expectedVersion: 1 })).statusCode, 201);
  assert.equal((await post(`/api/students/${enroll.studentId}/leaving`, { expectedVersion: 2, leftOn: "2026-09-15" })).statusCode, 201);
  assert.equal((await post(`/api/students/${enroll.studentId}/leaving/cancellation`, { expectedVersion: 3 })).statusCode, 201);
  assert.deepEqual(
    received.map((r) => `${r.path} ${r.commandType} ${r.issuedBy}`),
    ["open-academic-year admissions.OpenAcademicYear u1", "open-class admissions.OpenClass u1", "enroll-student admissions.EnrollStudent u1", "close-class admissions.CloseClass u1",
      "mark-student-left admissions.MarkStudentLeft u1", "cancel-student-leaving admissions.CancelStudentLeaving u1"],
  );
  assert.deepEqual(received[2].payload, enroll);
  assert.deepEqual(received[3].payload, { classId: enroll.classId, expectedVersion: 1 });
  assert.deepEqual(received[4].payload, { studentId: enroll.studentId, expectedVersion: 2, leftOn: "2026-09-15" });
  const future = await post(`/api/students/${enroll.studentId}/leaving`, { expectedVersion: 2, leftOn: "15 Sep", reason: " x " });
  assert.deepEqual(future.json().fields.map((f: { field: string }) => f.field).sort(), ["leftOn", "reason"]);
});

test("enrollment routes: wrong payloads come back by field, students get 403, the list is proxied", async () => {
  received.length = 0;
  const bad = await post("/api/classes", { academicYearId: "x", grade: "nursery", section: "A" });
  assert.equal(bad.statusCode, 400);
  assert.deepEqual(bad.json().fields.map((f: { field: string }) => f.field).sort(), ["academicYearId", "grade", "section"]);
  assert.equal((await post("/api/enrollments", { studentId: key, classId: key }, ["student"])).statusCode, 403);
  assert.equal(received.length, 0);
  const years = await app().inject({ url: "/api/academic-years", cookies: sessionCookie(["admin"]) });
  assert.equal(years.statusCode, 200);
  assert.equal(years.json()[0].name, "2026-27");
  assert.equal((await app().inject({ url: "/api/academic-years", cookies: sessionCookie(["teacher"]) })).statusCode, 403);
});

const put = (url: string, body: object, roles = ["admin"], origin = appUrl) =>
  app().inject({ method: "PUT", url, headers: { origin, "idempotency-key": key }, cookies: sessionCookie(roles), payload: body });

test("edit routes: the id in the path goes into the payload, each command goes to its admissions path", async () => {
  received.length = 0;
  const id = "0b8e6f3a-6a2e-4f7e-9a51-2f1d3c4b5a69";
  const other = "9c8b7a6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d";
  assert.equal((await put(`/api/students/${id}`, { ...student, studentId: other, expectedVersion: 2 })).statusCode, 201);
  assert.equal((await put(`/api/enrollments/${id}`, { classId: other, expectedVersion: 1 })).statusCode, 201);
  assert.equal((await put(`/api/academic-years/${id}`, { name: "2026-27", startsOn: "2026-04-01", endsOn: "2027-03-31", expectedVersion: 1 })).statusCode, 201);
  assert.deepEqual(
    received.map((r) => `${r.path} ${r.commandType}`),
    [
      "update-student-details admissions.UpdateStudentDetails",
      "change-student-class admissions.ChangeStudentClass",
      "update-academic-year admissions.UpdateAcademicYear",
    ],
  );
  assert.deepEqual(received[0].payload, { ...student, studentId: id, expectedVersion: 2 });
  assert.deepEqual(received[1].payload, { enrollmentId: id, classId: other, expectedVersion: 1 });
});

test("edit routes: no version, a bad id, a student user or a foreign origin are refused before admissions", async () => {
  received.length = 0;
  const noVersion = await put("/api/enrollments/0b8e6f3a-6a2e-4f7e-9a51-2f1d3c4b5a69", { classId: key });
  assert.equal(noVersion.statusCode, 400);
  assert.deepEqual(noVersion.json().fields.map((f: { field: string }) => f.field), ["expectedVersion"]);
  assert.equal((await put("/api/academic-years/x", { name: "2026-27", startsOn: "2026-04-01", endsOn: "2027-03-31", expectedVersion: 1 })).statusCode, 400);
  assert.equal((await put("/api/enrollments/0b8e6f3a-6a2e-4f7e-9a51-2f1d3c4b5a69", { classId: key, expectedVersion: 1 }, ["student"])).statusCode, 403);
  assert.equal((await put("/api/enrollments/0b8e6f3a-6a2e-4f7e-9a51-2f1d3c4b5a69", { classId: key, expectedVersion: 1 }, ["admin"], "https://evil.test")).statusCode, 403);
  assert.equal(received.length, 0);
});

test("fee routes: each command goes to the fees service with its type, ids from the path", async () => {
  received.length = 0;
  const id = "0b8e6f3a-6a2e-4f7e-9a51-2f1d3c4b5a69";
  const rs = (n: number) => ({ amount: n * 100, currency: "PKR" });
  assert.equal((await post("/api/fees/schedules", { academicYearId: id, grade: "class-3", monthlyFee: rs(4500) })).statusCode, 201);
  assert.equal((await post("/api/fees/payments", { accountId: id, amount: rs(4500), method: "cash" })).statusCode, 201);
  assert.equal((await post(`/api/fees/charges/${id}/reversal`, { reason: "Charged twice" })).statusCode, 201);
  assert.equal((await post(`/api/fees/payments/${id}/reversal`, { reason: "Entered twice" })).statusCode, 201);
  assert.deepEqual(
    received.map((r) => `${r.path} ${r.commandType} ${r.issuedBy}`),
    ["set-fee-schedule fees.SetFeeSchedule u1", "receive-payment fees.ReceivePayment u1", "reverse-charge fees.ReverseCharge u1", "reverse-payment fees.ReversePayment u1"],
  );
  assert.deepEqual(received[2].payload, { reason: "Charged twice", chargeId: id });
});

test("fee routes: bad money, a bad id or a teacher are refused before the fees service; reads are proxied", async () => {
  received.length = 0;
  const bad = await post("/api/fees/payments", { accountId: key, amount: { amount: 99, currency: "PKR" }, method: "card" });
  assert.equal(bad.statusCode, 400);
  assert.deepEqual(bad.json().fields.map((f: { field: string }) => f.field).sort(), ["amount.amount", "method"]);
  assert.equal((await post("/api/fees/charges/x/reversal", { reason: "x" })).statusCode, 400);
  assert.equal((await post("/api/fees/payments", { accountId: key, amount: { amount: 100, currency: "PKR" }, method: "cash" }, ["teacher"])).statusCode, 403);
  assert.equal(received.length, 0);
  const get = (url: string, roles = ["admin"]) => app().inject({ url, cookies: sessionCookie(roles) });
  assert.equal((await get("/api/fees/accounts")).json()[0].accountId, "a1");
  assert.equal((await get("/api/fees/schedules")).json()[0].grade, "class-3");
  assert.equal((await get(`/api/fees/accounts/${key}`)).json().accountId, key);
  assert.equal((await get("/api/fees/accounts/..%2Fstudents")).statusCode, 404);
  assert.equal((await get("/api/fees/accounts", ["student"])).statusCode, 403);
  const down = await app({ feesUrl: "http://127.0.0.1:9" }).inject({ url: "/api/fees/accounts", cookies: sessionCookie(["admin"]) });
  assert.equal(down.statusCode, 502);
  assert.match(down.json().error, /fees service did not answer/);
});
