# Dodo EDM design system (layout + styling)

This document is **prescriptive**. Follow it exactly. Do not invent new colors, layouts, or fonts.

## Approved palette (hex)
- Dodo Purple (brand): #470A68
- Dodo Teal (primary CTA): #0EE2B9
- Dodo Teal (alt): #0EE0B7
- Body Text: #353947
- Legal/Muted Text: #826696
- Light Gray Background: #E0E0E5
- Border Gray: #EBEBEE
- White: #FFFFFF

## Typography
- Font stack (all text): `font-family: Arial, Helvetica, sans-serif;`
- Base body text: 16px, line-height 24px, color #353947
- H1/hero heading: 26px, line-height 32px, color #470A68
- Section heading (H2): 20px, line-height 26px, color #470A68
- Small/support/legal: 12px, line-height 18px, color #826696

## Layout + container rules (must use tables)
- Use table-based layout with `role="presentation"`.
- Outer background: 100% width, background #E0E0E5.
- Inner container: centered, max-width 600px, width 100%.
- All content must live inside the 600px container.
- Use inline styles only.
- Do not use CSS classes or external CSS.

### Standard container spacing
- Default container padding: 24px 30px.
- Section spacing: 24px top/bottom between major blocks.
- Compact spacing: 12px top/bottom for small notes.

## Header / hero rules
- Header: white background, logo aligned left.
- Logo image must use this URL: https://image.email.dodo.com/lib/fe2711717d64047d7d1d79/m/1/4d591d48-bf10-4af5-ae8c-d4a2d33abada.jpg
- Logo max width: 140px; keep original aspect ratio.
- Hero image (optional): 600px wide, full-width inside container, `alt` text required.
- Hero heading must follow H1 styling above.

## CTA button styles (only these)
### Primary CTA
- Background: #0EE2B9
- Text color: #353947
- Border: 1px solid #0EE2B9
- Border radius: 3px
- Padding: 13px 55px
- Font: 13px Arial, Helvetica, sans-serif (bold)

```html
<a href="{{CTA_URL}}" style="background:#0EE2B9;border:1px solid #0EE2B9;border-radius:3px;color:#353947;display:inline-block;font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:bold;line-height:13px;text-align:center;text-decoration:none;padding:13px 55px;">
  {{CTA_LABEL}}
</a>
```

### Secondary CTA
- Background: #FFFFFF
- Text color: #470A68
- Border: 1px solid #470A68
- Border radius: 3px
- Padding: 13px 55px
- Font: 13px Arial, Helvetica, sans-serif (bold)

```html
<a href="{{CTA_URL}}" style="background:#FFFFFF;border:1px solid #470A68;border-radius:3px;color:#470A68;display:inline-block;font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:bold;line-height:13px;text-align:center;text-decoration:none;padding:13px 55px;">
  {{CTA_LABEL}}
</a>
```

## Content blocks
- Body copy must be left-aligned.
- Paragraph spacing: 0 0 16px 0 (use margin or spacing tables).
- Links in body text: color #470A68, underline.

## Footer rules
- Footer background: #FFFFFF
- Divider above footer: 1px solid #EBEBEE
- Footer padding: 20px 30px
- Legal text: 12px, line-height 18px, color #826696
- Required placeholders: postal address + unsubscribe link.

```html
<p style="margin:0 0 8px 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#826696;">
  {{BUSINESS_ADDRESS}}
</p>
<p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#826696;">
  <a href="{{UNSUBSCRIBE_URL}}" style="color:#470A68;text-decoration:underline;">Unsubscribe</a>
</p>
```
