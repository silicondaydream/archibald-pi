// Archibald UI.
//
// Everything shown here was written by someone else — possibly an attacker — so
// the one rule of this file: text is only ever set with textContent. No
// innerHTML, no insertAdjacentHTML, no string-built markup. The CSP enforces the
// rest (no inline script, no remote anything).

const $ = (sel) => document.querySelector(sel);

/** Build an element: el("div", {class: "x"}, child, "text", …). */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const SVG = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  return node;
}

// ---------------------------------------------------------------- API

async function post(path, body, isForm = false) {
  const res = await fetch(path, {
    method: "POST",
    headers: isForm ? undefined : { "Content-Type": "application/json" },
    body: isForm ? body : body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON error body */
  }
  if (!res.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : `Request failed (${res.status})`);
  }
  return data;
}

// ---------------------------------------------------------------- tabs & inputs

let kind = "auto";
let chosenFile = null;

function selectTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => {
    b.setAttribute("aria-selected", String(b.dataset.tab === name));
  });
  document.querySelectorAll(".pane").forEach((p) => {
    p.hidden = p.dataset.pane !== name;
  });
}

function setupInputs() {
  document.querySelectorAll(".tabs button").forEach((b) =>
    b.addEventListener("click", () => selectTab(b.dataset.tab)),
  );
  document.querySelectorAll(".segmented button").forEach((b) =>
    b.addEventListener("click", () => {
      kind = b.dataset.kind;
      document
        .querySelectorAll(".segmented button")
        .forEach((x) => x.setAttribute("aria-checked", String(x === b)));
    }),
  );

  $("#scan-text").addEventListener("click", () => {
    const text = $("#text-input").value;
    if (!text.trim()) return;
    run($("#scan-text"), () => post("/api/scan/text", { text, kind }));
  });
  $("#text-input").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") $("#scan-text").click();
  });

  $("#scan-url").addEventListener("click", () => {
    const url = $("#url-input").value.trim();
    if (!url) return;
    run($("#scan-url"), () => post("/api/scan/url", { url }));
  });
  $("#url-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#scan-url").click();
  });

  const drop = $("#drop");
  const input = $("#file-input");
  const choose = (file) => {
    chosenFile = file || null;
    $("#file-name").textContent = chosenFile
      ? `${chosenFile.name} · ${(chosenFile.size / 1024).toFixed(1)} KB`
      : "";
    $("#scan-file").disabled = !chosenFile;
  };
  input.addEventListener("change", () => choose(input.files[0]));
  ["dragenter", "dragover"].forEach((t) =>
    drop.addEventListener(t, (e) => {
      e.preventDefault();
      drop.classList.add("over");
    }),
  );
  ["dragleave", "drop"].forEach((t) =>
    drop.addEventListener(t, (e) => {
      e.preventDefault();
      drop.classList.remove("over");
    }),
  );
  drop.addEventListener("drop", (e) => choose(e.dataTransfer.files[0]));
  $("#scan-file").addEventListener("click", () => {
    if (!chosenFile) return;
    const form = new FormData();
    form.append("file", chosenFile);
    run($("#scan-file"), () => post("/api/scan/file", form, true));
  });
}

async function loadSamples() {
  try {
    const res = await fetch("/api/samples");
    const samples = await res.json();
    const list = $("#samples");
    for (const s of samples) {
      list.append(
        el(
          "button",
          {
            class: "sample",
            title: s.description,
            onclick: (e) => run(e.currentTarget, () => post(`/api/scan/sample/${s.id}`)),
          },
          s.title,
        ),
      );
    }
  } catch {
    /* samples are a convenience */
  }
  try {
    const health = await (await fetch("/api/health")).json();
    $("#version").textContent = `v${health.version}`;
  } catch {
    $("#version").textContent = "offline";
  }
}

async function run(button, request) {
  const label = button.textContent;
  button.classList.add("busy");
  button.disabled = true;
  if (button.classList.contains("primary")) button.textContent = "Scanning…";
  try {
    render(await request());
  } catch (err) {
    renderError(err.message);
  } finally {
    button.classList.remove("busy");
    button.disabled = button.id === "scan-file" ? !chosenFile : false;
    button.textContent = label;
  }
}

// ---------------------------------------------------------------- rendering

const LEVEL_TEXT = {
  clean: "Clean",
  suspicious: "Suspicious",
  likely: "Likely injection",
  injection: "Injection",
};

function ring(score, level) {
  const r = 50;
  const c = 2 * Math.PI * r;
  const box = svg("svg", { viewBox: "0 0 116 116", "aria-hidden": "true" });
  box.append(
    svg("circle", { cx: 58, cy: 58, r, fill: "none", "stroke-width": 9, class: "track" }),
  );
  const value = svg("circle", {
    cx: 58, cy: 58, r, fill: "none", "stroke-width": 9, "stroke-linecap": "round",
    class: `value lvl-${level}`, "stroke-dasharray": c, "stroke-dashoffset": c,
  });
  box.append(value);
  // Animate from empty on the next frame.
  requestAnimationFrame(() =>
    value.setAttribute("stroke-dashoffset", String(c * (1 - Math.max(score, 2) / 100))),
  );
  return el(
    "div",
    { class: "ring", role: "img", "aria-label": `Score ${score} out of 100` },
    box,
    el("div", { class: "ring-label" },
      el("div", { class: `ring-score lvl-${level}` }, score),
      el("div", { class: "ring-of" }, "of 100")),
  );
}

/** Evidence with the matched text wrapped in <mark> — built from text nodes. */
function evidence(text, match) {
  const pre = el("pre", { class: "evidence" });
  const i = match ? text.indexOf(match) : -1;
  if (i === -1) {
    pre.textContent = text;
  } else {
    pre.append(text.slice(0, i), el("mark", {}, match), text.slice(i + match.length));
  }
  return pre;
}

function findingCard(f) {
  return el(
    "div",
    { class: "finding", "data-category": f.category },
    el("div", { class: "finding-head" },
      el("span", { class: `sev sev-${f.severity}` }, f.severity),
      el("span", { class: "rule" }, f.rule),
      f.hidden ? el("span", { class: "badge" }, `hidden · ${f.hidden_reason}`) : null),
    el("p", { class: "message" }, f.message),
    el("div", { class: "where" }, f.location),
    evidence(f.evidence, f.match),
    f.decoded_from ? el("div", { class: "decoded" }, `Revealed by: ${f.decoded_from}`) : null,
  );
}

function render(v) {
  const results = $("#results");
  results.replaceChildren();

  const hiddenFindings = v.findings.filter((f) => f.hidden).length;
  results.append(
    el("div", { class: "card verdict" },
      ring(v.score, v.level),
      el("div", {},
        el("div", { class: `level lvl-${v.level}` }, LEVEL_TEXT[v.level] || v.level),
        el("p", { class: "summary" }, v.summary),
        el("div", { class: "stats" },
          stat("Input", v.input_kind),
          stat("Segments", v.segments_scanned),
          stat("Findings", v.findings.length),
          stat("In hidden content", hiddenFindings),
          stat("Hidden pieces", v.hidden.length)))),
  );

  if (v.findings.length) {
    const categories = [...new Set(v.findings.map((f) => f.category))];
    const list = el("div", {}, v.findings.map(findingCard));
    const filters = el("div", { class: "filters" });
    const setFilter = (cat) => {
      filters.querySelectorAll("button").forEach((b) =>
        b.setAttribute("aria-pressed", String(b.dataset.cat === cat)),
      );
      list.querySelectorAll(".finding").forEach((n) => {
        n.hidden = cat !== "all" && n.dataset.category !== cat;
      });
    };
    for (const cat of ["all", ...categories]) {
      const b = el("button", { class: "ghost", "aria-pressed": String(cat === "all") }, cat);
      b.dataset.cat = cat;
      b.addEventListener("click", () => setFilter(cat));
      filters.append(b);
    }
    results.append(
      el("div", { class: "card section" },
        el("div", { class: "section-head" },
          el("div", {},
            el("div", { class: "section-title" }, "Findings"),
            el("div", { class: "section-sub" }, "Most severe first. Hidden content is escalated.")),
          filters),
        list),
    );
  }

  if (v.hidden.length) {
    results.append(
      el("div", { class: "card section" },
        el("div", { class: "section-head" },
          el("div", {},
            el("div", { class: "section-title" }, "Revealed hidden content"),
            el("div", { class: "section-sub" },
              "Text a person would not see, but a model reading this input would."))),
        v.hidden.map((h) =>
          el("div", { class: "hidden-item" },
            el("div", { class: "hidden-meta" },
              el("span", { class: "badge" }, h.reason),
              el("span", { class: "where" }, h.location)),
            el("pre", { class: "evidence" }, h.text)),
        )),
    );
  }

  const json = JSON.stringify(v, null, 2);
  results.append(
    el("div", { class: "card" },
      v.notes.length ? el("ul", { class: "notes" }, v.notes.map((n) => el("li", {}, n))) : null,
      el("details", { class: "raw" },
        el("summary", {}, "Raw JSON verdict"),
        el("div", { class: "row end" },
          el("button", {
            class: "ghost",
            onclick: async (e) => {
              await navigator.clipboard?.writeText(json).catch(() => undefined);
              e.currentTarget.textContent = "Copied";
            },
          }, "Copy JSON")),
        el("pre", {}, json))),
  );
}

function stat(label, value) {
  return el("span", { class: "stat" }, `${label} `, el("b", {}, String(value)));
}

function renderError(message) {
  $("#results").replaceChildren(
    el("div", { class: "card error" }, el("strong", {}, "Couldn't scan that. "), message),
  );
}

setupInputs();
loadSamples();
