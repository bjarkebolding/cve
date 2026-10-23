(() => {
  const out = {};
  out.overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
  out.inks = ["chart-cves", "chart-hours", "chart-aipkgs", "chart-adoption", "chart-sev", "chart-kev"].map((id) => {
    const c = document.querySelector("#" + id + " canvas");
    if (!c || !c.width) return id + ":zero";
    let a = 0, b = 0;
    const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
    for (let i = 0; i < d.length; i += 32) { b++; if (d[i] > 20 || d[i + 1] > 20 || d[i + 2] > 20) a++; }
    return id + ":" + Math.round((100 * a) / b) + "%";
  });
  out.rows = document.querySelectorAll("#tbl-ai tbody tr").length;
  out.err = document.querySelector(".panel .err") ? "yes" : "no";
  // exercise the share mode on the main chart
  const u = document.querySelector("#chart-cves")._u;
  const share = document.querySelector("#ctl-cves [data-mode=share]");
  const count = document.querySelector("#ctl-cves [data-mode=count]");
  share.click();
  out.shareLabel = u.axes[1].label;
  count.click();
  out.countLabel = u.axes[1].label;
  return JSON.stringify(out);
})()
