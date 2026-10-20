import { describe, expect, it } from "vitest";

import { strings } from "../src/strings";

describe("strings", () => {
  it("follows the first supported browser language and falls back to English", () => {
    expect(strings(["es-ES", "en"]).join).toBe("Unirse");
    expect(strings(["fr", "en-GB"]).join).toBe("Join");
    expect(strings(["de"]).join).toBe("Join");
  });

  it("keeps the PRD messages verbatim in English", () => {
    const t = strings(["en"]);
    expect(t.waiting).toBe("Waiting for the sharer to let you in");
    expect(t.denied).toBe("The sharer declined your request");
    expect(t.notFound).toBe("This share has ended or the link is wrong. Ask for a new link.");
    expect(t.incomplete).toBe("This link is incomplete — the part after # is missing. Copy the whole link.");
    expect(t.badKey).toBe("This link's key is not valid. It may have been revoked.");
    expect(t.full).toBe("This share has reached its viewer limit.");
    expect(t.unreachable("relay.example")).toBe("Can't reach relay.example. Check your connection.");
    expect(t.unsupported).toBe("This browser isn't supported. Use a current Chrome, Firefox or Safari.");
    expect(t.sharerAway).toBe("Sharing computer is unreachable — reconnecting…");
    expect(t.offline).toBe("The sharing computer went offline. The share has ended.");
  });
});
