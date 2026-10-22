const HISTORY_KEY = "podpis_ecc_history";

function $(id) {
  return document.getElementById(id);
}

function show(el, html, kind) {
  el.classList.remove("hidden", "ok", "bad", "warn");
  if (kind) el.classList.add(kind);
  el.innerHTML = html;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadText(text, filename) {
  downloadBlob(new Blob([text], { type: "application/x-pem-file" }), filename);
}

async function readJsonSafe(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(text || "Nieprawidłowa odpowiedź serwera");
  }
}

function loadHistory() {
  try {
    return JSON.parse(sessionStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveHistory(items) {
  sessionStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 40)));
}

function addHistory(entry) {
  const items = loadHistory();
  items.unshift({
    t: new Date().toLocaleTimeString("pl-PL"),
    ...entry,
  });
  saveHistory(items);
  renderHistory();
}

function renderHistory() {
  const list = $("history-list");
  const items = loadHistory();
  if (!items.length) {
    list.innerHTML = '<li class="empty">Brak zdarzeń w tej sesji.</li>';
    return;
  }
  list.innerHTML = items
    .map((i) => `<li>[${i.t}] ${escapeHtml(i.text)}</li>`)
    .join("");
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

$("btn-clear-history").addEventListener("click", () => {
  sessionStorage.removeItem(HISTORY_KEY);
  renderHistory();
});

function setupDrops() {
  document.querySelectorAll(".drop").forEach((zone) => {
    const inputId = zone.dataset.input;
    const input = $(inputId);
    const label = document.querySelector(`.drop-file[data-for="${inputId}"]`);

    const syncName = () => {
      label.textContent = input.files?.[0]
        ? `${input.files[0].name} (${formatBytes(input.files[0].size)})`
        : "";
    };

    zone.addEventListener("click", () => input.click());
    zone.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        input.click();
      }
    });
    input.addEventListener("change", syncName);

    ["dragenter", "dragover"].forEach((ev) => {
      zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach((ev) => {
      zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.remove("dragover");
      });
    });
    zone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files?.[0];
      if (!file) return;
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      syncName();
    });
  });
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

$("btn-generate").addEventListener("click", async () => {
  const btn = $("btn-generate");
  const box = $("keys-result");
  const pass = $("gen-pass").value;
  const pass2 = $("gen-pass2").value;
  btn.disabled = true;
  try {
    const fd = new FormData();
    fd.append("passphrase", pass);
    fd.append("passphrase_confirm", pass2);
    const res = await fetch("/api/generate-keys", { method: "POST", body: fd });
    const data = await readJsonSafe(res);
    if (!res.ok) throw new Error(data.error || "Błąd generowania kluczy");

    const warn = data.encrypted
      ? `<p class="meta">Klucz prywatny zaszyfrowany hasłem (AES-256-CBC).</p>`
      : `<p><strong>Uwaga:</strong> klucz prywatny nie jest zaszyfrowany. Nie udostępniaj pliku i rozważ hasło przy generowaniu.</p>`;

    show(
      box,
      `${data.encrypted ? "" : ""}${warn}
       <p>Wygenerowano parę ECDSA (secp256r1) w ${data.keygen_ms} ms.</p>
       <div class="actions">
         <a href="#" id="dl-priv">Pobierz klucz prywatny</a>
         <a href="#" id="dl-pub">Pobierz klucz publiczny</a>
       </div>`,
      data.encrypted ? "ok" : "warn"
    );
    $("dl-priv").onclick = (e) => {
      e.preventDefault();
      if (!data.encrypted) {
        const ok = confirm(
          "Pobierasz NIEZASZYFROWANY klucz prywatny. Nie wysyłaj go nikomu i trzymaj lokalnie. Kontynuować?"
        );
        if (!ok) return;
      }
      downloadText(data.private_pem, "private.pem");
      addHistory({ text: "Pobrano klucz prywatny" + (data.encrypted ? " (zaszyfrowany)" : " (bez hasła)") });
    };
    $("dl-pub").onclick = (e) => {
      e.preventDefault();
      downloadText(data.public_pem, "public.pem");
      addHistory({ text: "Pobrano klucz publiczny" });
    };
    addHistory({
      text: `Wygenerowano klucze (${data.encrypted ? "z hasłem" : "bez hasła"}, ${data.keygen_ms} ms)`,
    });
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${escapeHtml(err.message)}</p>`, "bad");
    addHistory({ text: `Błąd generowania: ${err.message}` });
  } finally {
    btn.disabled = false;
  }
});

$("btn-preview-hash").addEventListener("click", async () => {
  const input = $("sign-doc");
  const box = $("sign-preview");
  if (!input.files?.[0]) {
    show(box, "<p>Najpierw wybierz dokument.</p>", "bad");
    return;
  }
  const fd = new FormData();
  fd.append("document", input.files[0]);
  try {
    const res = await fetch("/api/hash", { method: "POST", body: fd });
    const data = await readJsonSafe(res);
    if (!res.ok) throw new Error(data.error || "Nie udało się policzyć skrótu");
    show(
      box,
      `<p>Podgląd SHA-256 przed podpisem:</p><pre>${data.sha256}</pre>
       <p class="meta">${formatBytes(data.bytes)} · ${data.hash_ms} ms</p>`,
      "ok"
    );
    addHistory({ text: `Podgląd SHA-256: ${data.sha256.slice(0, 16)}…` });
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${escapeHtml(err.message)}</p>`, "bad");
  }
});

$("form-sign").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector('button[type="submit"]');
  const box = $("sign-result");
  btn.disabled = true;
  try {
    const res = await fetch("/api/sign", { method: "POST", body: new FormData(form) });
    if (!res.ok) {
      const data = await readJsonSafe(res);
      throw new Error(data.error || "Podpisywanie nie powiodło się");
    }
    const blob = await res.blob();
    const hash = res.headers.get("X-Document-SHA256") || "";
    const hashMs = res.headers.get("X-Hash-Ms") || "";
    const signMs = res.headers.get("X-Sign-Ms") || "";
    const sigBytes = res.headers.get("X-Signature-Bytes") || "";
    downloadBlob(blob, "document.sig");
    show(
      box,
      `<p>Podpis pobrany jako <code>document.sig</code>.</p>
       ${hash ? `<p>SHA-256:</p><pre>${hash}</pre>` : ""}
       <p class="meta">hash ${hashMs} ms · sign ${signMs} ms · podpis ${sigBytes} B</p>`,
      "ok"
    );
    addHistory({ text: `Podpisano dokument (${signMs} ms, ${sigBytes} B)` });
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${escapeHtml(err.message)}</p>`, "bad");
    addHistory({ text: `Błąd podpisu: ${err.message}` });
  } finally {
    btn.disabled = false;
  }
});

$("form-verify").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button");
  const box = $("verify-result");
  btn.disabled = true;
  try {
    const res = await fetch("/api/verify", { method: "POST", body: new FormData(form) });
    const data = await readJsonSafe(res);
    if (!res.ok) throw new Error(data.error || "Weryfikacja nie powiodła się");

    if (data.valid) {
      show(
        box,
        `<p><strong>WYNIK: podpis PRAWIDŁOWY</strong></p>
         <p>SHA-256:</p><pre>${data.sha256}</pre>
         <p class="meta">hash ${data.hash_ms} ms · verify ${data.verify_ms} ms</p>`,
        "ok"
      );
      addHistory({ text: `Weryfikacja: PRAWIDŁOWY (${data.verify_ms} ms)` });
    } else {
      show(
        box,
        `<p><strong>WYNIK: podpis NIEPRAWIDŁOWY</strong></p>
         <p>Dokument mógł zostać zmieniony, podpis uszkodzony albo użyto niewłaściwego klucza.</p>
         <p>SHA-256:</p><pre>${data.sha256}</pre>
         <p class="meta">hash ${data.hash_ms} ms · verify ${data.verify_ms} ms</p>`,
        "bad"
      );
      addHistory({ text: "Weryfikacja: NIEPRAWIDŁOWY" });
    }
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${escapeHtml(err.message)}</p>`, "bad");
    addHistory({ text: `Błąd weryfikacji: ${err.message}` });
  } finally {
    btn.disabled = false;
  }
});

$("form-hash").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button");
  const box = $("hash-result");
  btn.disabled = true;
  try {
    const res = await fetch("/api/hash", { method: "POST", body: new FormData(form) });
    const data = await readJsonSafe(res);
    if (!res.ok) throw new Error(data.error || "Obliczanie skrótu nie powiodło się");
    show(
      box,
      `<p>SHA-256:</p><pre>${data.sha256}</pre>
       <p class="meta">${formatBytes(data.bytes)} · ${data.hash_ms} ms</p>`,
      "ok"
    );
    addHistory({ text: `SHA-256 policzony (${data.hash_ms} ms)` });
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${escapeHtml(err.message)}</p>`, "bad");
  } finally {
    btn.disabled = false;
  }
});

$("btn-bench").addEventListener("click", async () => {
  const btn = $("btn-bench");
  const box = $("bench-result");
  btn.disabled = true;
  show(box, "<p>Trwa pomiar (RSA-3072 keygen może chwilę zająć)…</p>", "warn");
  try {
    const fd = new FormData();
    fd.append("rounds", $("bench-rounds").value || "3");
    const res = await fetch("/api/benchmark", { method: "POST", body: fd });
    const data = await readJsonSafe(res);
    if (!res.ok) throw new Error(data.error || "Benchmark nie powiódł się");
    show(
      box,
      `<p>Średnie czasy z ${data.rounds} rund (ms):</p>
       <table class="bench">
         <tr><th></th><th>ECC P-256</th><th>RSA-3072</th></tr>
         <tr><td>Keygen</td><td>${data.ecc.keygen_ms}</td><td>${data.rsa3072.keygen_ms}</td></tr>
         <tr><td>Sign</td><td>${data.ecc.sign_ms}</td><td>${data.rsa3072.sign_ms}</td></tr>
         <tr><td>Verify</td><td>${data.ecc.verify_ms}</td><td>${data.rsa3072.verify_ms}</td></tr>
         <tr><td>Rozmiar podpisu</td><td>${data.ecc.signature_bytes} B</td><td>${data.rsa3072.signature_bytes} B</td></tr>
       </table>`,
      "ok"
    );
    addHistory({ text: `Benchmark ECC vs RSA (${data.rounds} rund)` });
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${escapeHtml(err.message)}</p>`, "bad");
  } finally {
    btn.disabled = false;
  }
});

setupDrops();
renderHistory();
