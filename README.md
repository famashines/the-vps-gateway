# the-vps-gateway

The gateway of the-vps: the BFF (backend for frontend) of the dashboard. The
browser talks only to this service, at `/api` on the same host. It does the
login with Keycloak (`/api/auth/*`, a sealed session cookie), checks the role
and the schema of each request, and sends commands to the services inside the
cluster. It was named the-vps-authentication until 2026-10-25.

Fastify and TypeScript. Node 24 runs the `.ts` files directly; `tsc` only
checks the types.

## Work on it

    npm ci
    npm run check   # type check
    npm test        # node:test
    npm start       # http://localhost:8080/api/health

## Endpoints

| Method | Path                 | Who            | Answer                                                     |
| ------ | -------------------- | -------------- | ---------------------------------------------------------- |
| GET    | `/api/health`        | everyone       | `{"status":"ok","release":"<commit>"}`                      |
| GET    | `/api/auth/login`    | everyone       | Redirect to Keycloak (PKCE). `?returnTo=/path` after login |
| GET    | `/api/auth/callback` | Keycloak       | Sets the session cookie, then redirects to `returnTo`      |
| POST   | `/api/auth/logout`   | signed in      | Clears the cookie; `{"redirect": "<Keycloak logout URL>"}` |
| GET    | `/api/me`            | signed in      | `{"sub","name","roles"}`, or 401                           |
| GET    | `/api/students`      | role `admin`   | The list from the admissions service; 401 or 403 for others |
| POST   | `/api/students`      | role `admin`   | Body: `RegisterStudentCommandPayloadV1`, header `Idempotency-Key: <uuid>` (the `commandId`). 400 with `fields` when invalid, else the answer of admissions (201, or 200 for a repeated key), 502 when it does not answer |
| GET    | `/api/academic-years` | role `admin`  | Years with their classes, from admissions                  |
| POST   | `/api/academic-years` | role `admin`  | `OpenAcademicYearCommandPayloadV1`, the same rules as `POST /api/students` |
| POST   | `/api/classes`        | role `admin`  | `OpenClassCommandPayloadV1`, the same rules                |
| POST   | `/api/classes/:classId/closure` | role `admin` | `CloseClassCommandPayloadV1` (`expectedVersion`), the same rules. 409 while the class has students |
| POST   | `/api/enrollments`    | role `admin`  | `EnrollStudentCommandPayloadV1`, the same rules            |
| PUT    | `/api/students/:studentId` | role `admin` | `UpdateStudentDetailsCommandPayloadV1` without `studentId` (the path gives it), the same rules. 409 when `expectedVersion` is old |
| POST   | `/api/students/:studentId/leaving` | role `admin` | `MarkStudentLeftCommandPayloadV1` (`expectedVersion`, `leftOn`, optional `reason`), the same rules. 422 for a day in the future or before the admission date, 409 when the student has left |
| POST   | `/api/students/:studentId/leaving/cancellation` | role `admin` | `CancelStudentLeavingCommandPayloadV1` (`expectedVersion`), the same rules. 409 when the student has not left |
| PUT    | `/api/students/:studentId/photo` | role `admin` | Body: the picture (`image/jpeg`, `image/png` or `image/webp`, at most 1 MiB). Goes to admissions with the user id in `Issued-By`. 204 when saved, 400 for a bad id, 413 when too large, 415 for another type |
| GET    | `/api/students/:studentId/photo` | role `admin` | The photo from admissions, 404 when there is none |
| PUT    | `/api/enrollments/:enrollmentId` | role `admin` | `ChangeStudentClassCommandPayloadV1` (`classId`, `expectedVersion`), the same rules |
| PUT    | `/api/academic-years/:academicYearId` | role `admin` | `UpdateAcademicYearCommandPayloadV1`, the same rules |
| GET    | `/api/fees/schedules` | role `admin`  | The fee schedules, from the fees service |
| POST   | `/api/fees/schedules` | role `admin`  | `SetFeeScheduleCommandPayloadV1`, the same rules as `POST /api/students` |
| GET    | `/api/fees/accounts`  | role `admin`  | All fee accounts with their balance |
| GET    | `/api/fees/accounts/:accountId` | role `admin` | One account with its charges and payments; 404 for an id that is not a UUID |
| POST   | `/api/fees/payments`  | role `admin`  | `ReceivePaymentCommandPayloadV1`, the same rules |
| POST   | `/api/fees/charges/:chargeId/reversal` | role `admin` | `ReverseChargeCommandPayloadV1` (only `reason` in the body) |
| POST   | `/api/fees/payments/:paymentId/reversal` | role `admin` | `ReversePaymentCommandPayloadV1` (only `reason` in the body) |

## Session

The session is an AES-256-GCM sealed cookie `__Host-vps_session`
(HttpOnly, Secure, SameSite=Lax, 8 hours). It holds the user id, the name,
the realm roles and the ID token for the logout. The browser never gets an
access token. A `POST` (or any request that is not `GET`, `HEAD` or `OPTIONS`)
must have `Origin` equal to `APP_URL`.

## Settings

| Variable             | Example                                     |
| -------------------- | ------------------------------------------- |
| `APP_URL`            | `https://dev.app.vision.ac.pk`              |
| `OIDC_ISSUER`        | `https://auth.vision.ac.pk/realms/the-vps`  |
| `OIDC_CLIENT_ID`     | `the-vps-bff`                               |
| `OIDC_CLIENT_SECRET` | secret                                      |
| `SESSION_KEY`        | secret, 32 bytes in base64                  |
| `ADMISSIONS_URL`     | `http://the-vps-admissions`                 |
| `FEES_URL`           | `http://the-vps-fees`                       |

## Telemetry

`npm start` loads `src/telemetry.ts` first (`node --import`). It is the same
file in the 3 services:

- Traces: OpenTelemetry, OTLP HTTP to Tempo. Spans for each request (http
  and `@fastify/otel`, with `http.route`), for each call to a service
  (undici, with the `traceparent` header) and for each SQL query (pg). The
  health and ready probes and `/metrics` are not traced.
- Metrics: a Prometheus exporter on port `9464` (`METRICS_PORT`), for example
  `http_server_request_duration` (seconds) by `http_route`, never by the raw path.
- Logs: each line has `trace_id` and `span_id` when a span is active, so a log
  line in Loki links to its trace in Tempo.

| Variable                      | Example                                  |
| ----------------------------- | ---------------------------------------- |
| `OTEL_SERVICE_NAME`           | `the-vps-gateway`                        |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://tempo.monitoring.svc:4318`       |
| `OTEL_RESOURCE_ATTRIBUTES`    | `deployment.environment.name=the-vps-dev` |
| `OTEL_SDK_DISABLED`           | `true` turns the telemetry off           |

The tests import `app.ts` and do not load the telemetry. At shutdown, the spans
of the last 5 seconds can be lost.

## Release

A merge to `main` builds `ghcr.io/famashines/the-vps-gateway:sha-<commit>`
and releases it to dev through a pull request in `famashines/gitops`. Each pull
request runs the type check, the tests and an image build.
