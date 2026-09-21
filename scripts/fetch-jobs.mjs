// Fetches published jobs from Workable's public (keyless) widget API
// and writes them to jobs.json at the repo root, ready for roles.html to render.
//
// This uses Workable's public careers-widget endpoint - the same one their own
// hosted careers page calls - so no API token or login is required.

import { writeFileSync } from "fs";

const WORKABLE_SUBDOMAIN = "live-2-help-recruitment";
const WIDGET_URL = `https://apply.workable.com/api/v1/widget/accounts/${WORKABLE_SUBDOMAIN}`;

async function main() {
  const res = await fetch(WIDGET_URL, {
    headers: { "User-Agent": "Live2Help-CareerHub-JobSync/1.0" },
  });

  if (!res.ok) {
    throw new Error(`Workable widget request failed: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();
  const jobsRaw = data.jobs || [];

  const jobs = jobsRaw.map((j) => ({
    title: j.title,
    department: j.department || null,
    location: [j.city, j.state, j.country].filter(Boolean).join(", ") || (j.telecommuting ? "Remote" : "Location TBC"),
    remote: !!j.telecommuting,
    employment_type: j.employment_type || null,
    url: j.url || j.shortlink || null,
    shortcode: j.shortcode,
    published_on: j.published_on || null,
  }));

  const output = {
    updated_at: new Date().toISOString(),
    count: jobs.length,
    jobs,
  };

  writeFileSync("jobs.json", JSON.stringify(output, null, 2) + "\n");
  console.log(`Wrote ${jobs.length} job(s) to jobs.json`);
}

main().catch((err) => {
  console.error("Failed to fetch jobs:", err);
  process.exit(1);
});
