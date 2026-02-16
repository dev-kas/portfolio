const cheerio = require("cheerio");
const axios = require("axios");

const filters = {};

// sort and dedupe classes
filters["sortAndDedupeClasses"] = ($) => {
  $("[class]").each((_, el) => {
    const $el = $(el);
    const classAttr = $el.attr("class");

    if (!classAttr || !classAttr.trim()) return;

    const sortedClasses = [...new Set(classAttr.split(/\s+/).filter(Boolean))]
      .sort()
      .join(" ");

    $el.attr("class", sortedClasses);
  });
};

// sort attributes alphabetically
filters["sortAttributesAlphabetically"] = ($) => {
  $("*").each((_, el) => {
    const attrs = el.attribs;
    const keys = Object.keys(attrs);

    if (keys.length < 2) return;

    keys.sort();

    const sortedAttrs = {};
    keys.forEach((key) => {
      sortedAttrs[key] = attrs[key];
    });

    el.attribs = sortedAttrs;
  });
};

// inline the stylesheet
filters["inlineStylesheet"] = async ($, opts) => {
  const links = $('link[rel="stylesheet"][href]:not([href=""])').toArray();

  for (const el of links) {
    const noInline = $(el).attr("noinline");
    if (noInline !== undefined) continue;

    const href = $(el).attr("href");

    const base = new URL(opts.host);
    const resolved = new URL(href, base);

    if (resolved.origin !== base.origin) {
      console.warn(
        `[TinyPrint]: Using external stylesheet resource: \`${resolved.href}\``,
      );
    }

    const response = await axios.get(resolved.href);
    const stylesheet = response.data;

    $(el).replaceWith(`<style>${stylesheet}</style>`);
  }
};

// inline the scripts
filters["inlineScripts"] = async ($, opts) => {
  const scripts = $('script[src]:not([src=""])').toArray();

  for (const el of scripts) {
    const noInline = $(el).attr("noinline");
    if (noInline !== undefined) continue;

    const src = $(el).attr("src");

    const base = new URL(opts.host);
    const resolved = new URL(src, base);

    if (resolved.origin !== base.origin) {
      console.warn(
        `[TinyPrint]: Using external script resource: \`${resolved.href}\``,
      );
    }

    const response = await axios.get(resolved.href);
    const script = response.data;

    $(el).replaceWith(
      `<script type=${JSON.stringify($(el).attr("type") || "javascript")}>${script}</script>`,
    );
  }
};

// tiny helper
function useOptions(options = {}, defaults = {}) {
  return { ...defaults, ...options };
}

const defaultOptions = {
  filters: Object.values(filters),
  host: "http://localhost:1337/",
};

class TinyPrint {
  constructor(options) {
    this.options = useOptions(options, defaultOptions);
    this.filters = this.options.filters; // alias
  }

  /**
   * @param {string} input - HTML string
   * @param {object} options - Cheerio load options
   */
  async process(input, options = {}) {
    const defaultOpts = {
      decodeEntities: false,
    };

    const isDocument = options.isDocument || false;
    const $ = cheerio.load(input, useOptions(defaultOpts, options), isDocument);

    for (const filter of this.filters) {
      await filter.call(this, $, this.options);
    }

    return $.html();
  }
}

module.exports = { TinyPrint };
