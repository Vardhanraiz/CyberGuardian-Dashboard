document.getElementById("open-dashboard").addEventListener("click", () => {
  chrome.tabs.create({
    url: "https://cyberguardian-dashboard-ggfqyuzklwutasomre44wp.streamlit.app/"
  });
});
