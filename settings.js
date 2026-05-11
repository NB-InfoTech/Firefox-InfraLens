document.addEventListener("DOMContentLoaded", () => {
  const container = document.getElementById("featureToggles");
  let currentSettings = { ...FEATURE_DEFAULTS };

  getFeatureSettings((settings) => {
    currentSettings = settings;
    renderToggles(container, currentSettings);
  });

  document.getElementById("enableAll").onclick = () => {
    currentSettings = Object.fromEntries(
      Object.keys(FEATURE_DEFAULTS).map((feature) => [feature, true])
    );
    saveFeatureSettings(currentSettings, () => renderToggles(container, currentSettings));
  };

  document.getElementById("disableAll").onclick = () => {
    currentSettings = Object.fromEntries(
      Object.keys(FEATURE_DEFAULTS).map((feature) => [feature, false])
    );
    saveFeatureSettings(currentSettings, () => renderToggles(container, currentSettings));
  };
});

function renderToggles(container, settings) {
  container.textContent = "";

  Object.entries(FEATURE_LABELS).forEach(([feature, label]) => {
    const row = document.createElement("label");
    row.className = "toggle";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = settings[feature] !== false;
    checkbox.onchange = () => {
      const nextSettings = {
        ...settings,
        [feature]: checkbox.checked
      };
      saveFeatureSettings(nextSettings, () => renderToggles(container, nextSettings));
    };

    const text = document.createElement("span");
    text.textContent = label;

    row.append(checkbox, text);
    container.append(row);
  });
}
