# Dodo brand style guide (EDM)

## Official logo
- Use the Dodo logo image below for headers and brand moments.
- Logo URL (must use): https://image.email.dodo.com/lib/fe2711717d64047d7d1d79/m/1/4d591d48-bf10-4af5-ae8c-d4a2d33abada.jpg

## Brand palette (hex)
- Dodo Purple: #470A68
- Dodo Teal: #0EE2B9
- Dodo Teal (alt): #0EE0B7
- Body Text: #353947
- Legal/Muted Text: #826696
- Light Gray Background: #E0E0E5
- Border Gray: #EBEBEE
- White: #FFFFFF

## Button styles
### Primary CTA
- Background: #0EE2B9
- Text color: #353947
- Border: 1px solid #0EE2B9
- Border radius: 3px
- Padding: 13px 55px
- Font: 13px Arial, Helvetica, sans-serif (bold)

### Secondary CTA
- Background: #FFFFFF
- Text color: #470A68
- Border: 1px solid #470A68
- Border radius: 3px
- Padding: 13px 55px
- Font: 13px Arial, Helvetica, sans-serif (bold)

## Allowed fonts
- Arial
- Helvetica
- sans-serif (fallback)

## Table layout skeleton
Use a simple, nested table structure with presentation roles for email compatibility:

```html
<table cellpadding="0" cellspacing="0" width="100%" role="presentation" style="min-width:100%;">
  <tr>
    <td align="center" style="padding: 0;">
      <table cellpadding="0" cellspacing="0" width="600" role="presentation" style="width:100%; max-width:600px;">
        <tr>
          <td style="padding: 20px 30px; font-family: Arial, Helvetica, sans-serif; color: #353947;">
            <!-- Module content here -->
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
```
