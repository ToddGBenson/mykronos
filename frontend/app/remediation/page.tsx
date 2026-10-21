import { permanentRedirect } from "next/navigation";

import { retiredRoute } from "@/lib/retired-routes";

/**
 * Retired: the remediation library is a section of Remediate today now.
 *
 * Permanent (308) rather than temporary, because the move is: there is one
 * remediation page and this path is never coming back. The redirect lands on
 * `#library`, so a bookmark to the library opens at the library rather than at
 * the top of the worklist above it.
 */
export default function RemediationPage(): never {
  permanentRedirect(retiredRoute("/remediation"));
}
