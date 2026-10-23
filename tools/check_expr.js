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
  return JSON.stringify(out);
})()
