import { describe, expect, it } from "vitest";
import { reportPreviewLines } from "../app/components/LibraryViews";

describe("report document preview", () => {
  it("removes archived web markup and keeps meaningful report prose", () => {
    const lines = reportPreviewLines(`
Report title
<!--/*--><![CDATA[/* ><!--*/
.node-blog-full .blog-content img {
border: 1px solid #000 !important;
}
/*--><!]]>*/
On 30 March 2021, the IRS [issued](https://example.test) a security alert.
----------------
![](https://example.test/screenshot.png "screenshot")
The campaign delivers a **previously undocumented *BlackSoul* RAT.**
| File Name | sample.exe |
| --- | --- |
\`\`\`
### Key Findings
来源：公开报告
`);

    expect(lines).toEqual([
      "Report title",
      "On 30 March 2021, the IRS issued a security alert.",
      "The campaign delivers a previously undocumented BlackSoul RAT.",
      "File Name · sample.exe",
      "### Key Findings",
      "来源：公开报告",
    ]);
  });
});
