import { permanentRedirect } from "next/navigation";

import { retiredRoute } from "@/lib/retired-routes";

/**
 * Retired: this is the Risk policy page now (TheHub #61137). Permanent (308).
 * The browser keeps a `#fragment` across a redirect that names none, so links
 * into a section of the old page still land on it.
 */
export default function DecisionsPage(): never {
  permanentRedirect(retiredRoute("/decisions"));
}
