package com.ps;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class Main {

    // ===== In-memory users (email -> User). Demo only. =====
    static final Map<String, User> USERS = new ConcurrentHashMap<>();

    // ===== In-memory reset tokens (token -> email). Demo only. =====
    static final Map<String, String> RESET_TOKENS = new ConcurrentHashMap<>();

    static final class User {
        final String name;
        final String email;
        final String passwordHash; // SHA-256 (base64)

        User(String name, String email, String passwordHash) {
            this.name = name; this.email = email; this.passwordHash = passwordHash;
        }

        User withPasswordHash(String newHash) {
            return new User(this.name, this.email, newHash);
        }
    }

    public static void main(String[] args) throws IOException {
        // Optional: seed a demo user so you can test password reset
        USERS.putIfAbsent("edap_user@maxxenergy.com",
                new User("EDAP Demo", "edap_user@maxxenergy.com", sha256("OldPassword123!")));

        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        // Redirect "/" -> /about
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Location", "/about");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });

        // Pretty About page (original)
        server.createContext("/about", new AboutHandler());

        // Registration (existing)
        server.createContext("/register", new RegisterHandler());

        // Password reset (new)
        server.createContext("/password/forgot", new ForgotPasswordHandler());
        server.createContext("/password/reset", new ResetPasswordHandler());

        // Serve everything under /assets/* from src/main/resources/static/*
        server.createContext("/assets", new StaticFileHandler("/static"));

        // Optional health check
        server.createContext("/health", ex -> {
            byte[] ok = "OK".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, ok.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(ok); }
        });

        System.out.println("Server running at http://localhost:" + port + "/about");
        System.out.println("Demo user for reset: edap_user@maxxenergy.com (OldPassword123!)");
        server.start();
    }

    /** === About page (with Register + Forgot Password links) === */
    static class AboutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String html = """
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8" />
                  <meta name="viewport" content="width=device-width, initial-scale=1" />
                  <title>About · MAXX Energy EDAP</title>
                  <style>
                    :root{
                      --bg:#0b0c10; --card:#111217; --ink:#e8eaf0; --muted:#99a1b3; --line:#1f2330;
                      --brand:#e22323; --brand2:#8b1111; --accent:#2dd4bf;
                    }
                    *{box-sizing:border-box}
                    html{scroll-behavior:smooth}
                    body{margin:0;background:linear-gradient(180deg,#0b0c10 0%, #0e1117 100%);color:var(--ink);
                         font: 15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
                    a{color:inherit}
                    .wrap{max-width:1100px;margin:0 auto;padding:0 20px}
                    header{position:sticky;top:0;z-index:40;background:#0c0f15cc;
                           backdrop-filter:saturate(160%) blur(8px);border-bottom:1px solid var(--line)}
                    .nav{display:flex;align-items:center;justify-content:space-between;padding:14px 0}
                    .brand{display:flex;align-items:center;gap:12px}
                    .brand img{width:32px;height:32px;border-radius:8px;box-shadow:0 0 0 3px #00000055}
                    .chip{font-weight:700;letter-spacing:.2px}
                    .links a{padding:6px 10px;border-radius:10px;text-decoration:none;color:var(--muted)}
                    .links a:hover{background:#1a1f2b;color:var(--ink)}
                    .hero{border-bottom:1px solid var(--line);padding:56px 0}
                    .hero-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:28px;align-items:center}
                    @media (max-width:920px){.hero-grid{grid-template-columns:1fr}}
                    h1{font-size:44px;line-height:1.1;margin:0}
                    .lead{margin-top:12px;color:var(--muted);font-size:18px}
                    .cta{margin-top:18px;display:flex;gap:12px;flex-wrap:wrap}
                    .btn{padding:12px 16px;border-radius:14px;border:1px solid var(--line);text-decoration:none}
                    .btn.primary{background:linear-gradient(180deg,var(--brand),var(--brand2));border:0;color:white}
                    .panel{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px}
                    section{padding:42px 0}
                    #mission,#history,#team,#contact{scroll-margin-top:80px}
                    h2{font-size:26px;margin:0 0 10px}
                    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:24px}
                    @media (max-width:920px){.grid2{grid-template-columns:1fr}}
                    .timeline{border-left:2px solid var(--line);padding-left:16px;margin-top:8px}
                    .tl{position:relative;margin:14px 0}
                    .tl::before{content:"";position:absolute;left:-11px;top:6px;width:10px;height:10px;background:var(--accent);border-radius:50%}
                    .cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
                    @media (max-width:920px){.cards{grid-template-columns:1fr}}
                    .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px}
                    .muted{color:var(--muted)}
                    dl{display:grid;grid-template-columns:140px 1fr;gap:6px 18px}
                    footer{border-top:1px solid var(--line);color:var(--muted);text-align:center;padding:26px 0}
                    .logo-hero{background:#050507;border:1px solid var(--line);border-radius:16px;padding:22px;
                               display:flex;align-items:center;justify-content:center}
                    .logo-hero img{max-width:360px;width:100%;height:auto;filter:drop-shadow(0 8px 24px #00000080)}
                    ul{margin:8px 0 0 20px}
                  </style>
                </head>
                <body>
                  <header>
                    <div class="wrap nav">
                      <div class="brand">
                       <img src="/assets/maxx-energy-logo.png" alt="MAXX Energy logo">
                        <span class="chip">MAXX Energy · EDAP</span>
                      </div>
                      <nav class="links" aria-label="Primary">
                        <a href="#mission">Mission</a>
                        <a href="#history">History</a>
                        <a href="#team">Team</a>
                        <a href="/register">Register</a>
                        <a href="/password/forgot">Forgot password?</a>
                        <a href="#contact">Contact</a>
                      </nav>
                    </div>
                  </header>

                  <section class="hero">
                    <div class="wrap hero-grid">
                      <div>
                        <h1>About the Enterprise Data Access Portal</h1>
                        <p class="lead">
                          EDAP gives MAXX Energy stakeholders on-demand, trustworthy access to solar plant
                          generation and revenue data. Public insights for everyone, secure detail for authorized roles.
                        </p>
                        <div class="cta">
                          <a class="btn primary" href="/register">Create your account</a>
                          <a class="btn" href="#mission">Our mission</a>
                        </div>
                      </div>
                      <div class="logo-hero panel">
                        <img src="/assets/maxx-energy-logo.png" alt="MAXX Energy logo large">
                      </div>
                    </div>
                  </section>

                  <main class="wrap">
                    <section id="mission">
                      <div class="panel">
                        <h2>Our Mission</h2>
                        <p class="muted">Deliver a secure, human-friendly portal that exposes the right energy data to the right users at the right time.</p>
                        <div class="grid2" style="margin-top:14px">
                          <div>
                            <ul>
                              <li>Public data viewable without login</li>
                              <li>Private data secured with authentication & role-based authorization (executive, director, manager, staff)</li>
                              <li>Clear visualizations with filters and drilldowns</li>
                              <li>Well-defined APIs between Application, Data, and Security</li>
                            </ul>
                          </div>
                          <div class="card">
                            <strong>Definition of Done (sample)</strong>
                            <ul>
                              <li>Accessible page, responsive on mobile/desktop</li>
                              <li>Contact info visible</li>
                              <li>Team + history present</li>
                            </ul>
                          </div>
                        </div>
                      </div>
                    </section>

                    <section id="history">
                      <div class="panel">
                        <h2>Our History</h2>
                        <div class="timeline">
                          <div class="tl"><strong>2019</strong> — Concept for a unified energy data portal.</div>
                          <div class="tl"><strong>2022</strong> — Pilot with internal stakeholders.</div>
                          <div class="tl"><strong>2024</strong> — Role-based access model refined.</div>
                          <div class="tl"><strong>2025</strong> — Cohort-led build: public + private views with 8–10 visualizations.</div>
                        </div>
                      </div>
                    </section>

                    <section id="team">
                      <div class="cards">
                        <div class="card">
                          <h3>Agile Coach / Scrum Master</h3>
                          <p class="muted">Leads planning, standups, and manages dependencies across DevOps, Data, Security.</p>
                        </div>
                        <div class="card">
                          <h3>DevOps</h3>
                          <p class="muted">Builds the web app, APIs, and UI—ensuring smooth, responsive access to data.</p>
                        </div>
                        <div class="card">
                          <h3>Data & Security</h3>
                          <p class="muted">Embeds visualizations with filters/drilldowns and protects private data via authz/authn.</p>
                        </div>
                      </div>
                    </section>

                    <section id="contact">
                      <div class="panel">
                        <h2>Contact Us</h2>
                        <p class="muted">We usually respond within one business day.</p>
                        <dl style="margin-top:10px">
                          <dt>Email</dt><dd><a href="mailto:edap@maxxenergy.com">edap@maxxenergy.com</a></dd>
                          <dt>Phone</dt><dd><a href="tel:+11234567890">+1 (123) 456-7890</a></dd>
                          <dt>Address</dt><dd>123 Solar Way, New York, NY 10001</dd>
                          <dt>Social</dt><dd><a href="#">LinkedIn</a> · <a href="#">YouTube</a></dd>
                        </dl>
                      </div>
                    </section>
                  </main>

                  <footer>© 2025 MAXX Energy · Enterprise Data Access Portal</footer>
                </body>
                </html>
                """;

            byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
        }
    }

    /** === Registration page + POST handler === */
    static class RegisterHandler implements HttpHandler {
        @Override public void handle(HttpExchange ex) throws IOException {
            String method = ex.getRequestMethod();
            if ("GET".equalsIgnoreCase(method)) {
                writeHtml(ex, 200, registerFormHtml(null, null, null, null));
                return;
            }
            if ("POST".equalsIgnoreCase(method)) {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String,String> form = parseUrlEncoded(body);

                String name = trim(form.get("name"));
                String email = trim(form.get("email"));
                String password = trim(form.get("password"));

                String err = null;
                if (isEmpty(name) || isEmpty(email) || isEmpty(password)) {
                    err = "All fields are required.";
                } else if (!isEmailish(email)) {
                    err = "Please enter a valid email.";
                } else {
                    String pwdErr = passwordStrengthError(password);
                    if (pwdErr != null) err = pwdErr;
                }

                if (err != null) {
                    writeHtml(ex, 400, registerFormHtml(name, email, "", err));
                    return;
                }

                String key = email.toLowerCase();
                if (USERS.containsKey(key)) {
                    writeHtml(ex, 409, registerFormHtml(name, email, "", "That email is already registered."));
                    return;
                }

                String hash = sha256(password);
                USERS.put(key, new User(name, email, hash));
                writeHtml(ex, 201, successHtml(name, email, "Registration complete", "Back to About", "/about"));
                return;
            }

            ex.getResponseHeaders().add("Allow", "GET, POST");
            ex.sendResponseHeaders(405, -1);
        }
    }

    /** === Forgot Password: GET shows email form, POST “sends” reset link === */
    static class ForgotPasswordHandler implements HttpHandler {
        @Override public void handle(HttpExchange ex) throws IOException {
            String method = ex.getRequestMethod();
            if ("GET".equalsIgnoreCase(method)) {
                writeHtml(ex, 200, forgotFormHtml(null, null));
                return;
            }
            if ("POST".equalsIgnoreCase(method)) {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String,String> form = parseUrlEncoded(body);
                String email = trim(form.get("email"));
                String normalized = email == null ? null : email.toLowerCase();

                if (!isEmailish(email)) {
                    writeHtml(ex, 400, forgotFormHtml(email, "Please enter a valid email."));
                    return;
                }

                if (normalized != null && USERS.containsKey(normalized)) {
                    String token = generateToken();
                    RESET_TOKENS.put(token, normalized);
                    String link = "http://localhost:8080/password/reset?token=" + urlEncode(token);
                    // “Send” email by printing to server console for this demo
                    System.out.println("=== Password reset link for " + email + " ===");
                    System.out.println(link);
                }

                // Always show the same success message (avoid user enumeration)
                writeHtml(ex, 200, infoHtml(
                        "Check your email",
                        "If an account exists for " + escape(email) + ", a password reset link has been sent.",
                        "Back to About", "/about"));
                return;
            }

            ex.getResponseHeaders().add("Allow", "GET, POST");
            ex.sendResponseHeaders(405, -1);
        }
    }

    /** === Reset Password: GET shows form if token is valid, POST sets new password === */
    static class ResetPasswordHandler implements HttpHandler {
        @Override public void handle(HttpExchange ex) throws IOException {
            String method = ex.getRequestMethod();
            String rawQuery = ex.getRequestURI().getRawQuery();
            String token = getQueryParam(rawQuery, "token");

            if (token == null || !RESET_TOKENS.containsKey(token)) {
                writeHtml(ex, 400, infoHtml("Invalid or expired link",
                        "Your password reset link is invalid or has expired. Please request a new one.",
                        "Request new link", "/password/forgot"));
                return;
            }

            String email = RESET_TOKENS.get(token);

            if ("GET".equalsIgnoreCase(method)) {
                writeHtml(ex, 200, resetFormHtml(token, null));
                return;
            }

            if ("POST".equalsIgnoreCase(method)) {
                String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String,String> form = parseUrlEncoded(body);
                String newPwd = trim(form.get("password"));
                String confirm = trim(form.get("confirm"));

                String err = null;
                if (isEmpty(newPwd) || isEmpty(confirm)) {
                    err = "Both password fields are required.";
                } else if (!Objects.equals(newPwd, confirm)) {
                    err = "Passwords do not match.";
                } else {
                    String pwdErr = passwordStrengthError(newPwd);
                    if (pwdErr != null) err = pwdErr;
                }

                if (err != null) {
                    writeHtml(ex, 400, resetFormHtml(token, err));
                    return;
                }

                // Update user password
                String key = email.toLowerCase();
                User u = USERS.get(key);
                if (u != null) {
                    USERS.put(key, u.withPasswordHash(sha256(newPwd)));
                }
                // Invalidate token
                RESET_TOKENS.remove(token);

                writeHtml(ex, 200, successHtml(email, email,
                        "Password updated",
                        "Back to About", "/about"));
                return;
            }

            ex.getResponseHeaders().add("Allow", "GET, POST");
            ex.sendResponseHeaders(405, -1);
        }
    }

    // ---------- HTML templates ----------
    private static String registerFormHtml(String name, String email, String password, String error) {
        String html = """
        <!doctype html>
        <html lang="en"><head>
          <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
          <title>Create account · EDAP</title>
          <style>
            :root{--bg:#0b0c10; --card:#111217; --ink:#e8eaf0; --muted:#99a1b3; --line:#1f2330; --brand:#e22323; --brand2:#8b1111;}
            body{margin:0;background:linear-gradient(180deg,#0b0c10 0%, #0e1117 100%);color:var(--ink);
                 font:15px/1.55 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
            .wrap{max-width:520px;margin:48px auto;padding:0 18px}
            .card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px}
            h1{margin:0 0 10px}
            label{display:block;margin:12px 0 6px}
            input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid var(--line);background:#0d1017;color:var(--ink)}
            .actions{margin-top:16px;display:flex;gap:10px;flex-wrap:wrap}
            .btn{padding:12px 16px;border-radius:14px;border:1px solid var(--line);text-decoration:none;color:var(--ink)}
            .btn.primary{background:linear-gradient(180deg,var(--brand),var(--brand2));border:0;color:white}
            .muted{color:var(--muted)}
            .error{background:#2a0f12;border:1px solid #522;color:#f8caca;padding:10px;border-radius:12px;margin:10px 0}
            .hint{margin-top:10px;color:var(--muted);font-size:13px}
          </style>
        </head><body>
          <div class="wrap">
            <div class="card">
              <h1>Create your account</h1>
              <p class="muted">Access member-only features with a free account.</p>
              {{ERROR}}
              <form method="POST" action="/register">
                <label for="name">Full name</label>
                <input id="name" name="name" value="{{NAME}}" required />

                <label for="email">Email</label>
                <input id="email" type="email" name="email" value="{{EMAIL}}" required />

                <label for="password">Password</label>
                <input id="password" type="password" name="password" value="{{PASSWORD}}" minlength="8" required />
                <div class="hint">Use 8+ characters with upper, lower, number, and symbol.</div>

                <div class="actions">
                  <button class="btn primary" type="submit">Create account</button>
                  <a class="btn" href="/about">Cancel</a>
                  <a class="btn" href="/password/forgot">Forgot password?</a>
                </div>
              </form>
            </div>
          </div>
        </body></html>
        """;
        html = html.replace("{{ERROR}}", error != null ? "<div class=\"error\">" + escape(error) + "</div>" : "");
        html = html.replace("{{NAME}}", escapeOrEmpty(name));
        html = html.replace("{{EMAIL}}", escapeOrEmpty(email));
        html = html.replace("{{PASSWORD}}", escapeOrEmpty(password));
        return html;
    }

    private static String forgotFormHtml(String email, String error) {
        String html = """
        <!doctype html><html lang="en"><head>
          <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
          <title>Reset your password</title>
          <style>
            :root{--bg:#0b0c10; --card:#111217; --ink:#e8eaf0; --muted:#99a1b3; --line:#1f2330; --brand:#e22323; --brand2:#8b1111;}
            body{margin:0;background:linear-gradient(180deg,#0b0c10,#0e1117);color:var(--ink);
                 font:15px/1.55 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
            .wrap{max-width:520px;margin:48px auto;padding:0 18px}
            .card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px}
            label{display:block;margin:12px 0 6px}
            input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid var(--line);background:#0d1017;color:var(--ink)}
            .btn{padding:12px 16px;border-radius:14px;border:1px solid var(--line);text-decoration:none;color:var(--ink)}
            .btn.primary{background:linear-gradient(180deg,var(--brand),var(--brand2));border:0;color:white}
            .error{background:#2a0f12;border:1px solid #522;color:#f8caca;padding:10px;border-radius:12px;margin:10px 0}
            .actions{margin-top:16px;display:flex;gap:10px;flex-wrap:wrap}
          </style></head><body>
          <div class="wrap">
            <div class="card">
              <h1>Forgot your password?</h1>
              <p class="muted">Enter your email and we'll send you a reset link.</p>
              {{ERROR}}
              <form method="POST" action="/password/forgot">
                <label for="email">Email</label>
                <input id="email" type="email" name="email" value="{{EMAIL}}" required />
                <div class="actions">
                  <button class="btn primary" type="submit">Send reset link</button>
                  <a class="btn" href="/about">Cancel</a>
                </div>
              </form>
            </div>
          </div>
        </body></html>
        """;
        html = html.replace("{{ERROR}}", error != null ? "<div class=\"error\">" + escape(error) + "</div>" : "");
        html = html.replace("{{EMAIL}}", escapeOrEmpty(email));
        return html;
    }

    private static String resetFormHtml(String token, String error) {
        String html = """
        <!doctype html><html lang="en"><head>
          <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
          <title>Set a new password</title>
          <style>
            :root{--bg:#0b0c10; --card:#111217; --ink:#e8eaf0; --muted:#99a1b3; --line:#1f2330; --brand:#22c55e; --brand2:#15803d;}
            body{margin:0;background:linear-gradient(180deg,#0b0c10,#0e1117);color:var(--ink);
                 font:15px/1.55 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
            .wrap{max-width:520px;margin:48px auto;padding:0 18px}
            .card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px}
            label{display:block;margin:12px 0 6px}
            input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid var(--line);background:#0d1017;color:var(--ink)}
            .btn{padding:12px 16px;border-radius:14px;border:1px solid var(--line);text-decoration:none;color:var(--ink)}
            .btn.primary{background:linear-gradient(180deg,var(--brand),var(--brand2));border:0;color:white}
            .error{background:#2a0f12;border:1px solid #522;color:#f8caca;padding:10px;border-radius:12px;margin:10px 0}
            .hint{margin-top:10px;color:var(--muted);font-size:13px}
            .actions{margin-top:16px;display:flex;gap:10px;flex-wrap:wrap}
          </style></head><body>
          <div class="wrap">
            <div class="card">
              <h1>Set a new password</h1>
              {{ERROR}}
              <form method="POST" action="/password/reset?token={{TOKEN}}">
                <label for="password">New password</label>
                <input id="password" type="password" name="password" minlength="8" required />
                <div class="hint">Use 8+ characters with upper, lower, number, and symbol.</div>

                <label for="confirm">Confirm new password</label>
                <input id="confirm" type="password" name="confirm" minlength="8" required />

                <div class="actions">
                  <button class="btn primary" type="submit">Update password</button>
                  <a class="btn" href="/about">Cancel</a>
                </div>
              </form>
            </div>
          </div>
        </body></html>
        """;
        html = html.replace("{{ERROR}}", error != null ? "<div class=\"error\">" + escape(error) + "</div>" : "");
        html = html.replace("{{TOKEN}}", escapeOrEmpty(token));
        return html;
    }

    private static String successHtml(String name, String email, String title, String ctaText, String ctaHref) {
        String html = """
        <!doctype html><html lang="en"><head>
        <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Success</title>
        <style>
          body{margin:0;background:#0e1117;color:#e8eaf0;font:15px/1.55 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
          .wrap{max-width:720px;margin:40px auto;padding:0 16px}
          .card{background:#111217;border:1px solid #1f2330;border-radius:16px;padding:22px}
          a.btn{display:inline-block;margin-top:12px;padding:10px 14px;border-radius:12px;border:1px solid #1f2330;color:#e8eaf0;text-decoration:none}
          a.btn:hover{background:#1a1f2b}
        </style></head><body>
        <div class="wrap">
          <div class="card">
            <h2>{{TITLE}}</h2>
            <p>{{BODY1}}</p>
            <a class="btn" href="{{HREF}}">{{CTA}}</a>
          </div>
        </div>
        </body></html>
        """;
        String body = "Thanks, " + escapeOrEmpty(name) + ". Your account <strong>" + escapeOrEmpty(email) + "</strong> has been updated.";
        html = html.replace("{{TITLE}}", escapeOrEmpty(title));
        html = html.replace("{{BODY1}}", body);
        html = html.replace("{{CTA}}", escapeOrEmpty(ctaText));
        html = html.replace("{{HREF}}", escapeOrEmpty(ctaHref));
        return html;
    }

    private static String infoHtml(String title, String message, String ctaText, String ctaHref) {
        String html = """
        <!doctype html><html lang="en"><head>
        <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>{{TITLE}}</title>
        <style>
          body{margin:0;background:#0e1117;color:#e8eaf0;font:15px/1.55 system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
          .wrap{max-width:720px;margin:40px auto;padding:0 16px}
          .card{background:#111217;border:1px solid #1f2330;border-radius:16px;padding:22px}
          a.btn{display:inline-block;margin-top:12px;padding:10px 14px;border-radius:12px;border:1px solid #1f2330;color:#e8eaf0;text-decoration:none}
          a.btn:hover{background:#1a1f2b}
          .muted{color:#99a1b3}
        </style></head><body>
        <div class="wrap">
          <div class="card">
            <h2>{{TITLE}}</h2>
            <p class="muted">{{MSG}}</p>
            <a class="btn" href="{{HREF}}">{{CTA}}</a>
          </div>
        </div>
        </body></html>
        """;
        html = html.replace("{{TITLE}}", escapeOrEmpty(title));
        html = html.replace("{{MSG}}", escapeOrEmpty(message));
        html = html.replace("{{CTA}}", escapeOrEmpty(ctaText));
        html = html.replace("{{HREF}}", escapeOrEmpty(ctaHref));
        return html;
    }

    /** Static file handler for /assets/*  → loads from /static in classpath resources */
    static class StaticFileHandler implements HttpHandler {
        private final String resourceRoot; // e.g., "/static"
        StaticFileHandler(String resourceRoot) { this.resourceRoot = resourceRoot; }

        @Override public void handle(HttpExchange ex) throws IOException {
            String path = ex.getRequestURI().getPath().replaceFirst("^/assets", "");
            if (path.isEmpty() || "/".equals(path)) path = "/index.html"; // not used, but safe default
            String resourcePath = resourceRoot + path;

            try (InputStream is = Main.class.getResourceAsStream(resourcePath)) {
                if (is == null) {
                    ex.sendResponseHeaders(404, -1);
                    return;
                }
                String ct = contentType(resourcePath);
                ex.getResponseHeaders().add("Content-Type", ct);
                byte[] data = is.readAllBytes();
                ex.sendResponseHeaders(200, data.length);
                try (OutputStream os = ex.getResponseBody()) { os.write(data); }
            }
        }

        private static String contentType(String path) {
            String p = Objects.requireNonNull(path).toLowerCase();
            if (p.endsWith(".jpg") || p.endsWith(".jpeg")) return "image/jpeg";
            if (p.endsWith(".png")) return "image/png";
            if (p.endsWith(".webp")) return "image/webp";
            if (p.endsWith(".svg")) return "image/svg+xml";
            if (p.endsWith(".css")) return "text/css; charset=utf-8";
            if (p.endsWith(".js"))  return "application/javascript; charset=utf-8";
            if (p.endsWith(".html"))return "text/html; charset=utf-8";
            if (p.endsWith(".mp4")) return "video/mp4";
            return "application/octet-stream";
        }
    }

    // ===== helpers =====
    static void writeHtml(HttpExchange ex, int status, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    static Map<String,String> parseUrlEncoded(String body) {
        Map<String,String> out = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) return out;
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            String k = urlDecode(kv[0]);
            String v = kv.length > 1 ? urlDecode(kv[1]) : "";
            out.put(k, v);
        }
        return out;
    }

    static String urlDecode(String s) { return URLDecoder.decode(s, StandardCharsets.UTF_8); }
    static String urlEncode(String s) { return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8); }
    static boolean isEmpty(String s) { return s == null || s.isBlank(); }
    static String trim(String s) { return s == null ? null : s.trim(); }

    static boolean isEmailish(String email) {
        if (email == null) return false;
        String e = email.trim();
        return e.contains("@") && e.contains(".") && e.length() >= 6;
    }

    /** Simple strength rule: >=8, upper, lower, digit, symbol. Returns error message or null if OK. */
    static String passwordStrengthError(String s) {
        if (s == null || s.length() < 8) return "Password must be at least 8 characters.";
        boolean upper=false, lower=false, digit=false, symbol=false;
        for (char c: s.toCharArray()) {
            if (Character.isUpperCase(c)) upper = true;
            else if (Character.isLowerCase(c)) lower = true;
            else if (Character.isDigit(c)) digit = true;
            else symbol = true;
        }
        if (!upper || !lower || !digit || !symbol) {
            return "Use upper, lower, number, and symbol in your password.";
        }
        return null;
    }

    static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(s.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static String escapeOrEmpty(String s) { return s == null ? "" : escape(s); }
    static String escape(String s) {
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace("\"","&quot;").replace("'","&#39;");
    }

    static String getQueryParam(String rawQuery, String key) {
        if (rawQuery == null || rawQuery.isEmpty()) return null;
        String[] pairs = rawQuery.split("&");
        for (String p : pairs) {
            String[] kv = p.split("=", 2);
            if (kv.length == 2 && urlDecode(kv[0]).equals(key)) return urlDecode(kv[1]);
        }
        return null;
    }

    static String generateToken() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
