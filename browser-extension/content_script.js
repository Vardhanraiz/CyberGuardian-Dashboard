(function () {
  // Only inject once
  if (window.__cyberguardian_injected) return;
  window.__cyberguardian_injected = true;

  // Create tooltip element
  const tooltip = document.createElement("div");
  tooltip.style.position = "fixed";
  tooltip.style.zIndex = "999999";
  tooltip.style.background = "#020617";
  tooltip.style.color = "#e5e7eb";
  tooltip.style.padding = "10px 12px";
  tooltip.style.borderRadius = "8px";
  tooltip.style.boxShadow = "0 6px 16px rgba(15,23,42,0.7)";
  tooltip.style.border = "1px solid #1f2937";
  tooltip.style.fontSize = "12px";
  tooltip.style.maxWidth = "260px";
  tooltip.style.display = "none";
  tooltip.style.fontFamily = "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";

  tooltip.innerHTML = `
    <div style="font-weight:600; margin-bottom:4px; display:flex; align-items:center; gap:6px;">
      <span>🛡️</span> 
      <span>CyberGuardian Suggestion</span>
    </div>
    <div style="margin-bottom:6px;">
      Use a long, unique password and avoid reusing it on multiple sites.
    </div>
    <div style="margin-bottom:4px;">
      <b>Tip:</b> Enable 2FA for this account if available.
    </div>
    <a href="https://cyberguardian-dashboard-ggfqyuzklwutasomre44wp.streamlit.app/" 
       target="_blank" 
       style="color:#3b82f6; text-decoration:none; font-weight:500; font-size:11px;">
       Open CyberGuardian Dashboard
    </a>
  `;

  document.body.appendChild(tooltip);

  function showTooltipNear(input) {
    const rect = input.getBoundingClientRect();
    const top = rect.top + window.scrollY - 10;
    const left = rect.left + window.scrollX + rect.width + 10;

    tooltip.style.top = `${top}px`;
    tooltip.style.left = `${left}px`;
    tooltip.style.display = "block";
  }

  function hideTooltip() {
    tooltip.style.display = "none";
  }

  document.addEventListener("focusin", (event) => {
    const target = event.target;
    if (target && target.tagName === "INPUT" && target.type === "password") {
      showTooltipNear(target);
    } else {
      hideTooltip();
    }
  });

  document.addEventListener("click", (event) => {
    if (!tooltip.contains(event.target)) {
      // Optional: hide tooltip on click outside
      // hideTooltip();
    }
  });
})();
