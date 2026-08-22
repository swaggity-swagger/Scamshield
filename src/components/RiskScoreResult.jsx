import React, { useMemo } from "react";

/**
 * RiskScoreResult
 * ---------------
 * Drop this into src/components/RiskScoreResult.jsx
 * Replace the `result` mock object with your FastAPI response —
 * field names are documented inline.
 *
 * Fonts expected in index.html:
 *   Fraunces (display) + Inter (body) + JetBrains Mono (gauge readout)
 */

const mockResult = {
  score: 78, // 0-100, higher = more dangerous
  verdict: "Likely a Scam", // short human headline
  language: "English",
  channel: "WhatsApp message",
  evidence: [
    { label: "Urgent money request", detail: "Message pressures you to act within minutes." },
    { label: "Unknown bank link", detail: "The link does not match any real bank website." },
    { label: "Impersonating a relative", detail: "Sender claims to be a family member in trouble." },
  ],
  explanation:
    "This message uses fear and urgency to stop you from thinking carefully. Real banks and family members do not ask for money through unexpected links.",
  actions: [
    { id: "report", label: "Report this message", tone: "primary" },
    { id: "block", label: "Block this sender", tone: "secondary" },
    { id: "share", label: "Share with a trusted contact", tone: "secondary" },
  ],
};

function bandForScore(score) {
  if (score < 34) return { name: "safe", color: "#2F7D5B", label: "Looks Safe" };
  if (score < 67) return { name: "caution", color: "#C98A2B", label: "Be Careful" };
  return { name: "danger", color: "#B03A2E", label: "High Risk" };
}

function Gauge({ score }) {
  const band = bandForScore(score);
  // Needle sweeps -90deg (score 0) to +90deg (score 100) across a semicircle
  const angle = -90 + (score / 100) * 180;

  const arc = (startAngle, endAngle, color) => {
    const r = 120;
    const cx = 150;
    const cy = 150;
    const toXY = (deg) => {
      const rad = (deg * Math.PI) / 180;
      return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)];
    };
    const [x1, y1] = toXY(startAngle - 180);
    const [x2, y2] = toXY(endAngle - 180);
    const largeArc = endAngle - startAngle > 180 ? 1 : 0;
    return (
      <path
        d={`M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`}
        fill="none"
        stroke={color}
        strokeWidth="22"
        strokeLinecap="round"
      />
    );
  };

  return (
    <div className="relative w-[300px] h-[170px] mx-auto">
      <svg viewBox="0 0 300 170" className="w-full h-full overflow-visible">
        {arc(0, 60, "#2F7D5B")}
        {arc(60, 120, "#C98A2B")}
        {arc(120, 180, "#B03A2E")}
        {/* Needle */}
        <g transform={`rotate(${angle} 150 150)`}>
          <line x1="150" y1="150" x2="150" y2="45" stroke="#1B2A4A" strokeWidth="4" strokeLinecap="round" />
          <circle cx="150" cy="150" r="9" fill="#1B2A4A" />
        </g>
      </svg>
      <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
        <span
          className="font-mono text-4xl font-semibold tracking-tight"
          style={{ color: band.color }}
        >
          {score}
        </span>
        <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-[#5B6B6E]">
          risk score / 100
        </span>
      </div>
    </div>
  );
}

export default function RiskScoreResult({ result = mockResult }) {
  const band = useMemo(() => bandForScore(result.score), [result.score]);

  return (
    <div className="min-h-screen bg-[#EEF1ED] text-[#1E2A2F]" style={{ fontFamily: "Inter, sans-serif" }}>
      <div className="max-w-md mx-auto px-5 pb-28 pt-8">
        {/* Header */}
        <div className="flex items-center gap-2 mb-6">
          <div className="w-8 h-8 rounded-full bg-[#1B2A4A] flex items-center justify-center">
            <span className="text-[#EEF1ED] text-sm font-bold" style={{ fontFamily: "Fraunces, serif" }}>
              S
            </span>
          </div>
          <span className="text-sm font-medium text-[#5B6B6E]">
            ScamSense &middot; checked via {result.channel}
          </span>
        </div>

        {/* Hero: the gauge, the signature element */}
        <div
          className="rounded-3xl bg-white shadow-sm border border-[#E1E5DE] pt-8 pb-6 px-6"
        >
          <Gauge score={result.score} />
          <h1
            className="text-center text-3xl mt-4 font-semibold"
            style={{ fontFamily: "Fraunces, serif", color: band.color }}
          >
            {result.verdict}
          </h1>
          <p className="text-center text-sm text-[#5B6B6E] mt-1">
            Checked in {result.language}
          </p>
        </div>

        {/* Plain-language explanation */}
        <div className="mt-6 rounded-2xl bg-[#1B2A4A] text-[#EEF1ED] px-5 py-4">
          <p className="text-[15px] leading-relaxed">{result.explanation}</p>
        </div>

        {/* Evidence */}
        <div className="mt-6">
          <h2
            className="text-sm font-semibold uppercase tracking-wide text-[#5B6B6E] mb-3"
          >
            What we found
          </h2>
          <ul className="space-y-3">
            {result.evidence.map((item, i) => (
              <li
                key={i}
                className="flex gap-3 rounded-xl bg-white border border-[#E1E5DE] px-4 py-3"
              >
                <span
                  className="mt-0.5 w-2 h-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: band.color }}
                />
                <div>
                  <p className="text-[15px] font-medium">{item.label}</p>
                  <p className="text-sm text-[#5B6B6E] mt-0.5">{item.detail}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Sticky action bar */}
      <div className="fixed bottom-0 inset-x-0 bg-white border-t border-[#E1E5DE]">
        <div className="max-w-md mx-auto px-5 py-4 flex flex-col gap-2">
          {result.actions.map((action) => (
            <button
              key={action.id}
              className={
                action.tone === "primary"
                  ? "w-full rounded-xl py-3 text-[15px] font-semibold text-white"
                  : "w-full rounded-xl py-3 text-[15px] font-medium border border-[#D8DCD4] text-[#1E2A2F]"
              }
              style={
                action.tone === "primary" ? { backgroundColor: band.color } : undefined
              }
            >
              {action.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
