import cookie from "@fastify/cookie";
import Fastify, { type FastifyReply, type FastifyRequest, type FastifyServerOptions } from "fastify";
import * as oidc from "openid-client";
import { randomUUID } from "node:crypto";
import { sealer } from "./seal.ts";
import * as valid from "./validate.ts";

export type Settings = {
  appUrl: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  sessionKey: string;
  admissionsUrl: string;
  feesUrl: string;
  oidcConfig?: () => Promise<oidc.Configuration>;
};

export type Session = { sub: string; name: string; roles: string[]; idToken: string; exp: number };
type Login = { state: string; nonce: string; verifier: string; returnTo: string; exp: number };

declare module "fastify" {
  interface FastifyRequest {
    session?: Session;
  }
}

export const SESSION_COOKIE = "__Host-vps_session";
export const LOGIN_COOKIE = "__Host-vps_login";
const SESSION_SECONDS = 8 * 60 * 60;
const LOGIN_SECONDS = 10 * 60;
const cookieOptions = { httpOnly: true, secure: true, sameSite: "lax", path: "/" } as const;

const now = () => Math.floor(Date.now() / 1000);
const safeReturnTo = (value: unknown) =>
  typeof value === "string" && value.startsWith("/") && !value.startsWith("//") && !value.startsWith("/\\") ? value : "/";

export function requireRole(role: string) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.session) return reply.code(401).send({ error: "Sign in first." });
    if (!request.session.roles.includes(role)) return reply.code(403).send({ error: "You do not have access to this." });
  };
}

export function buildApp(settings: Settings, options: FastifyServerOptions = {}) {
  const app = Fastify(options);
  const release = process.env.RELEASE ?? "local";
  const box = sealer(settings.sessionKey);
  const redirectUri = `${settings.appUrl}/api/auth/callback`;

  let discovery: Promise<oidc.Configuration> | undefined;
  const oidcConfig =
    settings.oidcConfig ??
    (() => {
      discovery ??= oidc.discovery(new URL(settings.issuer), settings.clientId, settings.clientSecret).catch((error) => {
        discovery = undefined;
        throw error;
      });
      return discovery;
    });

  app.register(cookie);

  app.addHook("onRequest", async (request, reply) => {
    if (!["GET", "HEAD", "OPTIONS"].includes(request.method) && request.headers.origin !== settings.appUrl) {
      return reply.code(403).send({ error: "This request must come from the dashboard." });
    }
    const session = box.open<Session>(request.cookies[SESSION_COOKIE]);
    if (session && session.exp > now()) request.session = session;
  });

  app.get("/api/health", { logLevel: "warn" }, async () => ({ status: "ok", release }));

  app.get("/api/auth/login", async (request, reply) => {
    const config = await oidcConfig();
    const verifier = oidc.randomPKCECodeVerifier();
    const login: Login = {
      state: oidc.randomState(),
      nonce: oidc.randomNonce(),
      verifier,
      returnTo: safeReturnTo((request.query as Record<string, unknown>).returnTo),
      exp: now() + LOGIN_SECONDS,
    };
    reply.setCookie(LOGIN_COOKIE, box.seal(login), { ...cookieOptions, maxAge: LOGIN_SECONDS });
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope: "openid profile",
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: "S256",
      state: login.state,
      nonce: login.nonce,
    });
    return reply.redirect(url.href);
  });

  app.get("/api/auth/callback", async (request, reply) => {
    const login = box.open<Login>(request.cookies[LOGIN_COOKIE]);
    reply.clearCookie(LOGIN_COOKIE, cookieOptions);
    if (!login || login.exp <= now()) return reply.redirect("/?signin=failed");
    try {
      const tokens = await oidc.authorizationCodeGrant(await oidcConfig(), new URL(request.url, settings.appUrl), {
        pkceCodeVerifier: login.verifier,
        expectedState: login.state,
        expectedNonce: login.nonce,
        idTokenExpected: true,
      });
      const claims = tokens.claims()!;
      const session: Session = {
        sub: claims.sub,
        name: String(claims.name ?? claims.preferred_username ?? claims.sub),
        roles: Array.isArray(claims.roles) ? claims.roles.map(String) : [],
        idToken: tokens.id_token!,
        exp: now() + SESSION_SECONDS,
      };
      reply.setCookie(SESSION_COOKIE, box.seal(session), { ...cookieOptions, maxAge: SESSION_SECONDS });
      return reply.redirect(login.returnTo);
    } catch (error) {
      request.log.warn({ err: error }, "sign-in failed");
      return reply.redirect("/?signin=failed");
    }
  });

  app.post("/api/auth/logout", async (request, reply) => {
    const idToken = request.session?.idToken;
    reply.clearCookie(SESSION_COOKIE, cookieOptions);
    if (!idToken) return { redirect: "/" };
    const config = await oidcConfig();
    const url = oidc.buildEndSessionUrl(config, { id_token_hint: idToken, post_logout_redirect_uri: `${settings.appUrl}/` });
    return { redirect: url.href };
  });

  app.get("/api/me", async (request, reply) => {
    if (!request.session) return reply.code(401).send({ error: "Sign in first." });
    const { sub, name, roles } = request.session;
    return { sub, name, roles };
  });

  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  const service = (name: string, base: string) => async (reply: FastifyReply, path: string, init?: RequestInit) => {
    try {
      const response = await fetch(`${base}${path}`, { ...init, signal: AbortSignal.timeout(10_000) });
      return reply.code(response.status).type("application/json").send(await response.text());
    } catch (error) {
      reply.log.error({ err: error }, `${name} service unreachable`);
      return reply.code(502).send({ error: `The ${name} service did not answer. Try again in a minute.` });
    }
  };
  const admissions = service("admissions", settings.admissionsUrl);
  const fees = service("fees", settings.feesUrl);

  app.get("/api/students", { preHandler: requireRole("admin") }, async (_request, reply) => admissions(reply, "/students"));

  const command = (method: "POST" | "PUT", path: string, commandType: string, validPayload: typeof valid.validRegisterStudent, target: string, send = admissions) =>
    app.route({ method, url: path, preHandler: requireRole("admin"), handler: async (request, reply) => {
      const commandId = request.headers["idempotency-key"];
      if (typeof commandId !== "string" || !uuid.test(commandId)) {
        return reply.code(400).send({ error: "The Idempotency-Key header must be a UUID." });
      }
      const payload = { ...(request.body as object), ...(request.params as object) };
      if (!validPayload(payload)) {
        return reply.code(400).send({ error: "Check the marked fields.", fields: valid.fieldErrors(validPayload.errors) });
      }
      const envelope = {
        commandId,
        commandType,
        version: 1,
        issuedAt: new Date().toISOString(),
        issuedBy: request.session!.sub,
        correlationId: randomUUID(),
        payload,
      };
      return send(reply, target, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(envelope),
      });
    } });

  command("POST", "/api/students", "admissions.RegisterStudent", valid.validRegisterStudent, "/commands/register-student");
  command("POST", "/api/academic-years", "admissions.OpenAcademicYear", valid.validOpenAcademicYear, "/commands/open-academic-year");
  command("POST", "/api/classes", "admissions.OpenClass", valid.validOpenClass, "/commands/open-class");
  command("POST", "/api/classes/:classId/closure", "admissions.CloseClass", valid.validCloseClass, "/commands/close-class");
  command("POST", "/api/enrollments", "admissions.EnrollStudent", valid.validEnrollStudent, "/commands/enroll-student");
  command("PUT", "/api/students/:studentId", "admissions.UpdateStudentDetails", valid.validUpdateStudentDetails, "/commands/update-student-details");
  command("POST", "/api/students/:studentId/leaving", "admissions.MarkStudentLeft", valid.validMarkStudentLeft, "/commands/mark-student-left");
  command("POST", "/api/students/:studentId/leaving/cancellation", "admissions.CancelStudentLeaving", valid.validCancelStudentLeaving, "/commands/cancel-student-leaving");
  command("PUT", "/api/enrollments/:enrollmentId", "admissions.ChangeStudentClass", valid.validChangeStudentClass, "/commands/change-student-class");
  command("PUT", "/api/academic-years/:academicYearId", "admissions.UpdateAcademicYear", valid.validUpdateAcademicYear, "/commands/update-academic-year");

  app.addContentTypeParser(["image/jpeg", "image/png", "image/webp"], { parseAs: "buffer", bodyLimit: 1024 * 1024 }, (_request, body, done) => done(null, body));

  const photo = async (request: FastifyRequest, reply: FastifyReply) => {
    const { studentId } = request.params as { studentId: string };
    if (!uuid.test(studentId)) return reply.code(400).send({ error: "The student id must be a UUID." });
    const put = request.method === "PUT";
    try {
      const response = await fetch(`${settings.admissionsUrl}/students/${studentId}/photo`, {
        method: request.method,
        ...(put && { headers: { "content-type": String(request.headers["content-type"]), "issued-by": request.session!.sub }, body: new Uint8Array(request.body as Buffer) }),
        signal: AbortSignal.timeout(10_000),
      });
      reply.code(response.status);
      for (const name of ["content-type", "cache-control"]) {
        const value = response.headers.get(name);
        if (value) reply.header(name, value);
      }
      return reply.send(response.status === 204 ? undefined : Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      reply.log.error({ err: error }, "admissions service unreachable");
      return reply.code(502).send({ error: "The admissions service did not answer. Try again in a minute." });
    }
  };
  app.get("/api/students/:studentId/photo", { preHandler: requireRole("admin") }, photo);
  app.put("/api/students/:studentId/photo", { preHandler: requireRole("admin") }, photo);

  app.get("/api/academic-years", { preHandler: requireRole("admin") }, async (_request, reply) => admissions(reply, "/academic-years"));

  command("POST", "/api/fees/schedules", "fees.SetFeeSchedule", valid.validSetFeeSchedule, "/commands/set-fee-schedule", fees);
  command("POST", "/api/fees/payments", "fees.ReceivePayment", valid.validReceivePayment, "/commands/receive-payment", fees);
  command("POST", "/api/fees/charges/:chargeId/reversal", "fees.ReverseCharge", valid.validReverseCharge, "/commands/reverse-charge", fees);
  command("POST", "/api/fees/payments/:paymentId/reversal", "fees.ReversePayment", valid.validReversePayment, "/commands/reverse-payment", fees);

  app.get("/api/fees/schedules", { preHandler: requireRole("admin") }, async (_request, reply) => fees(reply, "/fee-schedules"));
  app.get("/api/fees/accounts", { preHandler: requireRole("admin") }, async (_request, reply) => fees(reply, "/accounts"));
  app.get<{ Params: { accountId: string } }>("/api/fees/accounts/:accountId", { preHandler: requireRole("admin") }, async (request, reply) =>
    uuid.test(request.params.accountId) ? fees(reply, `/accounts/${request.params.accountId}`) : reply.code(404).send({ error: "The account does not exist." }),
  );

  return app;
}
