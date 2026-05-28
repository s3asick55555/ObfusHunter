const form = document.getElementById("uploadForm");
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const statusBox = document.getElementById("status");
const analyzeBtn = document.getElementById("analyzeBtn");
const exportCard = document.getElementById("exportCard");
const jsonLink = document.getElementById("jsonLink");
const dropzoneTitle = dropzone.querySelector(".dropzone__title");
const dropzoneSubtitle = dropzone.querySelector(".dropzone__subtitle");

const summaryCard = document.getElementById("summaryCard");
const scoreRing = document.getElementById("scoreRing");
const scoreText = document.getElementById("scoreText");
const statusText = document.getElementById("statusText");
const fileMeta = document.getElementById("fileMeta");
const techniqueBadges = document.getElementById("techniqueBadges");
const signalsGrid = document.getElementById("signalsGrid");
const indicatorTable = document.getElementById("indicatorTable");
const sectionsTable = document.getElementById("sectionsTable");
const rawJson = document.getElementById("rawJson");

function bytesToHuman(bytes) {
	const units = ["B", "KB", "MB", "GB"];
	let value = Number(bytes || 0);
	let unit = 0;
	while (value >= 1024 && unit < units.length - 1) {
		value /= 1024;
		unit += 1;
	}
	return `${value.toFixed(2)} ${units[unit]}`;
}

function escapeHtml(value) {
	return String(value ?? "")
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

function severityClass(level) {
	const normalized = String(level || "").toLowerCase();
	if (normalized === "high") return "sev high";
	if (normalized === "medium") return "sev medium";
	if (normalized === "low") return "sev low";
	return "sev";
}

function setScore(score) {
	scoreRing.style.setProperty(
		"--score",
		`${Math.min(360, (score || 0) * 3.6)}deg`,
	);
	scoreText.textContent = score || 0;
}

function updateSelectedFile() {
	const file = fileInput.files?.[0];
	if (!file) {
		dropzone.classList.remove("has-file");
		dropzoneTitle.textContent = "Drop a file here";
		dropzoneSubtitle.textContent = "or click to browse";
		return;
	}
	dropzone.classList.add("has-file");
	dropzoneTitle.textContent = file.name;
	dropzoneSubtitle.textContent = `${bytesToHuman(file.size)} • ready to analyze`;
	statusBox.textContent = `Attached: ${file.name}`;
}

function renderSignals(data) {
	const packing = data.techniques?.pe_packing || {};
	const importObf = data.techniques?.import_obfuscation || {};
	const xor = data.techniques?.string_xor || {};
	const dead = data.techniques?.dead_code || {};
	const apiHash = data.techniques?.api_hashing || {};
	const xorIocs = data.techniques?.string_xor?.iocs || [];

	const cards = [
		["Entropy", data.pe?.total_entropy?.toFixed?.(2) ?? "n/a"],
		["High-entropy sections", (packing.high_entropy_sections || []).length],
		["Packer section names", (packing.packer_section_names || []).length],
		[
			"Dynamic API imports",
			(importObf.dynamic_resolution_apis || []).length,
		],
		["XOR keys", (xor.xor_keys || []).length],
		["Stack XOR hits", xor.stack_string_xor_count || 0],
		["Opaque predicates", dead.opaque_predicate_count || 0],
		["Sink blocks", dead.sink_vertex_count || 0],
		["Rotate ops", apiHash.rotate_count || 0],
		["IOC strings", xorIocs.length],
	];

	signalsGrid.innerHTML = "";
	cards.forEach(([label, value]) => {
		const div = document.createElement("div");
		div.className = "signal-card";
		div.innerHTML = `<h4>${escapeHtml(label)}</h4><p>${escapeHtml(value)}</p>`;
		signalsGrid.appendChild(div);
	});
}

function renderEvidence(evidence) {
	if (!evidence) return "";
	const toMono = (text) => `<span class="mono">${escapeHtml(text)}</span>`;
	const renderItem = (item) => {
		if (typeof item === "string") return `<li>${escapeHtml(item)}</li>`;
		if (item?.decoded) {
			const reason = item.reason ? ` (${escapeHtml(item.reason)})` : "";
			return `<li>${toMono(item.offset || "")}	${escapeHtml(item.decoded)}${reason}</li>`;
		}
		if (item?.mnemonic && item?.address) {
			const asm = [item.mnemonic, item.op_str].filter(Boolean).join(" ");
			return `<li>${toMono(`${item.section || ""} ${item.address} ${asm}`)}</li>`;
		}
		if (item?.block && item?.pattern) {
			return `<li>${toMono(`${item.block} ${item.pattern}`)}</li>`;
		}
		if (typeof item === "object") {
			return `<li>${toMono(JSON.stringify(item))}</li>`;
		}
		return `<li>${escapeHtml(String(item))}</li>`;
	};

	const chunks = [];
	if (Array.isArray(evidence)) {
		chunks.push(`<ul>${evidence.map(renderItem).join("")}</ul>`);
	} else if (typeof evidence === "object") {
		Object.entries(evidence).forEach(([key, value]) => {
			if (!value || (Array.isArray(value) && !value.length)) return;
			chunks.push(
				`<div class="evidence-group"><div class="evidence-label">${escapeHtml(key)}</div>`,
			);
			if (Array.isArray(value)) {
				chunks.push(`<ul>${value.map(renderItem).join("")}</ul>`);
			} else {
				chunks.push(`<div>${renderItem(value)}</div>`);
			}
			chunks.push("</div>");
		});
	}

	if (!chunks.length) return "";
	return `<details class="evidence"><summary>Evidence</summary>${chunks.join("")}</details>`;
}

function renderIndicators(indicators) {
	indicatorTable.innerHTML = "";
	if (!indicators || !indicators.length) {
		const tr = document.createElement("tr");
		tr.innerHTML = `<td colspan="5" class="muted">No scored indicators were triggered.</td>`;
		indicatorTable.appendChild(tr);
		return;
	}

	indicators.forEach((item) => {
		const tr = document.createElement("tr");
		const evidence = renderEvidence(item.evidence);
		tr.innerHTML = `
      <td><span class="${severityClass(item.severity)}">${escapeHtml(item.severity || "INFO")}</span></td>
      <td>${escapeHtml(item.indicator || "")}</td>
      <td>${escapeHtml(item.technique || "")}</td>
			<td>${escapeHtml(item.reason || "")}${evidence}</td>
      <td>${escapeHtml(item.points || 0)}</td>
    `;
		indicatorTable.appendChild(tr);
	});
}

function renderSections(sections) {
	sectionsTable.innerHTML = "";
	(sections || []).forEach((section) => {
		const tr = document.createElement("tr");
		tr.innerHTML = `
      <td class="mono">${escapeHtml(section.name)}</td>
      <td>${escapeHtml(section.entropy)}</td>
      <td>${escapeHtml(bytesToHuman(section.raw_size))}</td>
      <td>${escapeHtml(section.printable_ascii_ratio)}</td>
      <td>${(section.flags || []).map((flag) => `<span class="badge">${escapeHtml(flag)}</span>`).join(" ")}</td>
    `;
		sectionsTable.appendChild(tr);
	});
}

function renderBadges(techniques) {
	techniqueBadges.innerHTML = "";
	(techniques || []).forEach((tech) => {
		const span = document.createElement("span");
		span.className = "badge";
		span.textContent = tech;
		techniqueBadges.appendChild(span);
	});
}

function renderResult(data) {
	summaryCard.style.display = "block";

	const score = data.summary?.score || 0;
	setScore(score);
	statusText.textContent = data.summary?.status || "Unknown";

	const file = data.file || {};
	const pe = data.pe || {};
	const meta = [
		file.original_name || file.name,
		bytesToHuman(file.size),
		pe.architecture || "unknown",
	].filter(Boolean);
	fileMeta.textContent = meta.join(" • ");

	renderBadges(data.summary?.techniques || []);
	renderSignals(data);
	renderIndicators(data.indicators || []);
	renderSections(data.sections || []);

	rawJson.textContent = JSON.stringify(data, null, 2);

	if (data.report_id) {
		exportCard.style.display = "flex";
		jsonLink.href = `/api/report/${data.report_id}.json`;
	}
}

form.addEventListener("submit", async (event) => {
	event.preventDefault();

	if (!fileInput.files.length) {
		statusBox.textContent = "Choose a file first.";
		return;
	}

	const body = new FormData();
	body.append("file", fileInput.files[0]);

	analyzeBtn.disabled = true;
	statusBox.textContent = "Analyzing Windows PE obfuscation heuristics...";

	try {
		const response = await fetch("/api/analyze", { method: "POST", body });
		const data = await response.json();

		if (!response.ok) {
			throw new Error(data.error || "Analysis failed.");
		}

		statusBox.textContent = "Analysis complete.";
		renderResult(data);
	} catch (error) {
		statusBox.textContent = error.message;
	} finally {
		analyzeBtn.disabled = false;
	}
});

["dragenter", "dragover"].forEach((eventName) => {
	dropzone.addEventListener(eventName, (event) => {
		event.preventDefault();
		dropzone.classList.add("dragover");
	});
});

["dragleave", "drop"].forEach((eventName) => {
	dropzone.addEventListener(eventName, (event) => {
		event.preventDefault();
		dropzone.classList.remove("dragover");
	});
});

dropzone.addEventListener("drop", (event) => {
	if (event.dataTransfer.files.length) {
		fileInput.files = event.dataTransfer.files;
		updateSelectedFile();
	}
});

fileInput.addEventListener("change", updateSelectedFile);
