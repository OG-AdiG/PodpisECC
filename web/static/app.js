function $(id) {
  return document.getElementById(id);
}

function show(el, html, kind) {
  el.classList.remove("hidden", "ok", "bad");
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

$("btn-generate").addEventListener("click", async () => {
  const btn = $("btn-generate");
  const box = $("keys-result");
  btn.disabled = true;
  try {
    const res = await fetch("/api/generate-keys", { method: "POST" });
    const data = await readJsonSafe(res);
    if (!res.ok) throw new Error(data.error || "Błąd generowania kluczy");

    show(
      box,
      `<p>Wygenerowano parę kluczy ECDSA (secp256r1).</p>
       <div class="actions">
         <a href="#" id="dl-priv">Pobierz klucz prywatny</a>
         <a href="#" id="dl-pub">Pobierz klucz publiczny</a>
       </div>
       <p style="margin-top:0.75rem;color:var(--muted);font-size:0.85rem">
         Nie udostępniaj pliku prywatnego. Do weryfikacji wystarczy klucz publiczny.
       </p>`,
      "ok"
    );
    $("dl-priv").onclick = (e) => {
      e.preventDefault();
      downloadText(data.private_pem, "private.pem");
    };
    $("dl-pub").onclick = (e) => {
      e.preventDefault();
      downloadText(data.public_pem, "public.pem");
    };
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${err.message}</p>`, "bad");
  } finally {
    btn.disabled = false;
  }
});

$("form-sign").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector("button");
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
    downloadBlob(blob, "document.sig");
    show(
      box,
      `<p>Podpis utworzony i pobrany jako <code>document.sig</code>.</p>
       ${hash ? `<p>SHA-256 dokumentu:</p><pre>${hash}</pre>` : ""}`,
      "ok"
    );
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${err.message}</p>`, "bad");
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
      show(box, `<p><strong>WYNIK: podpis PRAWIDŁOWY</strong></p>
        <p>Dokument jest zgodny z podpisem i kluczem publicznym.</p>`, "ok");
    } else {
      show(
        box,
        `<p><strong>WYNIK: podpis NIEPRAWIDŁOWY</strong></p>
         <p>Dokument mógł zostać zmieniony, podpis uszkodzony albo użyto niewłaściwego klucza.</p>`,
        "bad"
      );
    }
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${err.message}</p>`, "bad");
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
    show(box, `<p>SHA-256:</p><pre>${data.sha256}</pre>`, "ok");
  } catch (err) {
    show(box, `<p><strong>Błąd:</strong> ${err.message}</p>`, "bad");
  } finally {
    btn.disabled = false;
  }
});
