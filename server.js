const express = require("express");
const { engine } = require("express-handlebars");
const path = require("path");
const hljs = require("highlight.js");
const feather = require("feather-icons");
const helmet = require("helmet");
const { TinyPrint } = require("./tinyprint");

const zlib = require("zlib");
const { promisify } = require("util");

const gzip = promisify(zlib.gzip);
const brotli = promisify(zlib.brotliCompress);

const data = require("./data");

const app = express();

// middlewares
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https://www.roblox.com"],
        "connect-src": ["'self'"],
        "font-src": ["'self'"],
        "object-src": ["'none'"],
        "upgrade-insecure-requests": [],
      },
    },
  }),
);
// vars
const PORT = Number(process.env.PORT) || 5500;
const CACHE_TTL = Number(process.env.CACHE_TTL) || 6 * 60 * 60 * 1000; // 6 hours
const REFRESH_BEFORE = Number(process.env.REFRESH_BEFORE) || 5 * 60 * 1000; // 5 minutes before expiry

// cache infra
const routeCache = new Map();

function createCacheEntry({ ttl, refreshBefore, generator }) {
  return {
    encodings: {
      identity: null,
      gzip: null,
      br: null,
    },
    lastGenerated: 0,
    isRegenerating: false,
    ttl,
    refreshBefore,
    generator,
  };
}

async function renderTemplate(view, data) {
  return new Promise((resolve, reject) => {
    app.render(view, data, (err, html) => {
      if (err) return reject(err);
      resolve(html);
    });
  });
}

async function regenerate(entry, path) {
  if (entry.isRegenerating) return;
  entry.isRegenerating = true;

  try {
    const start = performance.now();

    let newHtml = await entry.generator();
    newHtml = await tinyprint.process(newHtml, { isDocument: true });

    const gzipBuffer = await gzip(newHtml);
    const brotliBuffer = await brotli(newHtml, {
      params: {
        [zlib.constants.BROTLI_PARAM_QUALITY]: 11,
      },
    });

    const rawBytes = Buffer.byteLength(newHtml, "utf8");
    const gzipBytes = gzipBuffer.length;
    const brotliBytes = brotliBuffer.length;

    entry.encodings.identity = newHtml;
    entry.encodings.gzip = gzipBuffer;
    entry.encodings.br = brotliBuffer;

    entry.lastGenerated = Date.now();

    const duration = (performance.now() - start).toFixed(2);

    // instrumentation
    let log = `Generated for \`${path}\``;
    log += `\nRaw: ${rawBytes} bytes`;
    log += `\nGzip: ${gzipBytes} bytes`;
    log += `\nBrotli: ${brotliBytes} bytes`;
    log += `\nTime: ${duration}ms`;
    console.log(log);
  } catch (err) {
    console.error("Regeneration failed:", err);
    entry.encodings.identity = `
        <body style="background:#000;color:#ff2e2e;font-family:monospace;padding:50px;">
            <h1>[ CRITICAL_SYSTEM_FAILURE ]</h1>
            <p>The kernel encountered an unrecoverable error during page synthesis.</p>
            <pre>${process.env.NODE_ENV === "development" ? err.message : "Error: SIGABRT"}</pre>
            <a href="/" style="color:#fff;">Attempt Warm Reboot</a>
        </body>
    `;
  } finally {
    entry.isRegenerating = false;
  }
}

async function route(path, options) {
  const entry = createCacheEntry(options);
  routeCache.set(path, entry);

  app.get(path, async (req, res) => {
    const now = Date.now();
    const age = now - entry.lastGenerated;

    if (age > entry.ttl - entry.refreshBefore) {
      regenerate(entry, path); // background refresh
    }

    res.set("Vary", "Accept-Encoding");
    res.type("html");

    const accept = (req.headers["accept-encoding"] || "")
      .split(",")
      .map((s) => s.trim().split(";")[0]);

    // send first supported encoding, or fallback to raw
    for (const encoding of accept) {
      if (encoding in entry.encodings && entry.encodings[encoding]) {
        res.set("Content-Encoding", encoding);
        return res.send(entry.encodings[encoding]);
      }
    }

    // fallback
    res.send(entry.encodings.identity);
  });
}

// configure handlebars
app.engine(
  "handlebars",
  engine({
    defaultLayout: "main",
    helpers: {
      highlight(code, lang) {
        if (!code) return "";
        const validLang = hljs.getLanguage(lang) ? lang : "plaintext";
        try {
          return hljs.highlight(code, { language: validLang }).value;
        } catch (e) {
          return code;
        }
      },
      getLinkIcon(url) {
        if (!url) return "";
        if (url.includes("github.com")) return "github";
        return "external-link";
      },
      feather: function (name, options) {
        const icon = feather.icons[name];
        if (!icon) return "";
        return icon.toSvg({
          ...options.hash,
          "aria-hidden": "true",
          focusable: "false",
        });
      },
    },
  }),
);
app.set("view engine", "handlebars");
app.set("views", "./views");

// setup tinyprint for smaller footprints
const tinyprint = new TinyPrint({
  host: `http://localhost:${PORT}`,
});

// static folder for css/images
app.use(express.static(path.join(__dirname, "public")));

// routes
route("/", {
  ttl: CACHE_TTL,
  refreshBefore: REFRESH_BEFORE,
  generator: () => renderTemplate("index", data),
});

route("/404", {
  ttl: CACHE_TTL,
  refreshBefore: REFRESH_BEFORE,
  generator: () => renderTemplate("404", data),
});

app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send(
    `User-agent: *\nAllow: /\nSitemap: ${data.meta.siteUrl}/sitemap.xml`,
  );
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc>${data.meta.siteUrl}</loc>
		<lastmod>${new Date().toISOString().split("T")[0]}</lastmod>
		<changefreq>monthly</changefreq>
		<priority>1.0</priority>
	</url>
</urlset>`);
});

// 404 catch-all
app.use((req, res) => {
  const entry = routeCache.get("/404");

  res.status(404);
  res.set("Vary", "Accept-Encoding");
  res.type("html");

  const accept = (req.headers["accept-encoding"] || "")
    .split(",")
    .map((s) => s.trim().split(";")[0]);

  for (const encoding of accept) {
    if (encoding in entry.encodings && entry.encodings[encoding]) {
      res.set("Content-Encoding", encoding);
      return res.send(entry.encodings[encoding]);
    }
  }

  res.send(entry.encodings.identity);
});

app.listen(PORT, async () => {
  console.log(`Server running on https://localhost:${PORT}`);
  console.log(`Mode: Systems Online.`);

  console.log("Warming system cache...");
  for (const [path, entry] of routeCache.entries()) {
    await regenerate(entry, path);
  }
  console.log("Cache Synthesis Complete.");
});
