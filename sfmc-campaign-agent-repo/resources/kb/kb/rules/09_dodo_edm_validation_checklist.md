# Dodo EDM validation checklist (must pass)

Use this checklist to validate any generated EDM HTML before delivery. If any item fails, regenerate.

## Structure
- [ ] Uses the approved container shell (600px max-width table).
- [ ] Only `{{BODY_HTML}}` content changes; header/footer shell unchanged.
- [ ] All content is inside the 600px container.
- [ ] Table-based layout with `role="presentation"`.

## Colors
- [ ] All colors are from the approved palette only: #470A68, #0EE2B9, #0EE0B7, #353947, #826696, #E0E0E5, #EBEBEE, #FFFFFF.
- [ ] No other hex values appear.

## Typography
- [ ] Font stack is Arial, Helvetica, sans-serif.
- [ ] Body text is 16px/24px, color #353947.
- [ ] H1 is 26px/32px, color #470A68.
- [ ] H2 is 20px/26px, color #470A68.
- [ ] Legal text is 12px/18px, color #826696.

## CTAs
- [ ] CTA buttons use the approved primary/secondary HTML snippets verbatim.
- [ ] CTA background, border, text color, radius, padding match the design system.

## Header / footer
- [ ] Dodo logo URL is used and aligned left.
- [ ] Footer includes divider, `{{BUSINESS_ADDRESS}}`, and `{{UNSUBSCRIBE_URL}}` placeholders.

## Spacing
- [ ] Default container padding is 24px 30px.
- [ ] Section spacing uses 24px between major blocks.
- [ ] Compact spacing uses 12px for small notes.
