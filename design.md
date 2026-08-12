# Design — Simple M365 Relay

A locked design system for the v2 administration app. Extend this file when the
system grows; do not regenerate a different visual language per route.

## Genre

Modern-minimal operations console: calm, compact, technical, and explicit.

## Macrostructure family

- App pages: Workbench. Operational evidence and controls lead; explanation follows.
- Authentication pages: a narrow access panel beside a concise product statement.
- Content pages: Long Document for diagnostics and release documentation.

## Theme

- Paper: cool engineered near-white
- Ink: blue-black
- Accent: restrained cobalt, reserved for actions and focus
- Status: semantic success, warning, and destructive tokens only
- Radius: 6–10 px; no decorative pills or glass effects

## Typography

- Display and body: Geist Variable, normal style
- Mono: system monospace
- Display tracking: `-0.025em`

## Spacing and motion

- Four-point spacing scale exposed in `layout.css`
- Motion is functional and under 180 ms
- Reduced motion disables transform and smooth scrolling

## Component voice

- shadcn-svelte Nova components are the source of controls and surfaces
- Buttons name concrete actions
- Alerts explain recovery, not merely failure
- Empty states explain the next useful action
- App pages do not use decorative enrichment

## Compatibility

- Existing `/data/config/config.json`, administrator Argon2 hashes, and backup
  archives remain readable.
- Session cookies intentionally rotate during the v2 upgrade.

