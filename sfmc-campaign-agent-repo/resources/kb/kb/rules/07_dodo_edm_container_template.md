# Dodo EDM container template (do not alter)

**Instruction:** This template is the approved Dodo EDM shell. **Do not change this shell**. Only insert generated body content into the `{{BODY_HTML}}` placeholder.

## Container template (HTML)

```html
<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="min-width:100%;background:#E0E0E5;">
  <tr>
    <td align="center" style="padding:0;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="600" style="width:100%;max-width:600px;background:#FFFFFF;">
        <!-- Header -->
        <tr>
          <td style="padding:20px 30px;background:#FFFFFF;">
            <img src="https://image.email.dodo.com/lib/fe2711717d64047d7d1d79/m/1/4d591d48-bf10-4af5-ae8c-d4a2d33abada.jpg" width="140" alt="Dodo" style="display:block;border:0;outline:none;text-decoration:none;height:auto;" />
          </td>
        </tr>

        <!-- Body (insert content only) -->
        <tr>
          <td style="padding:24px 30px;font-family:Arial,Helvetica,sans-serif;color:#353947;font-size:16px;line-height:24px;">
            {{BODY_HTML}}
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:0 30px 0 30px;background:#FFFFFF;">
            <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-top:1px solid #EBEBEE;">
              <tr>
                <td style="padding:20px 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#826696;">
                  <p style="margin:0 0 8px 0;">{{BUSINESS_ADDRESS}}</p>
                  <p style="margin:0;">
                    <a href="{{UNSUBSCRIBE_URL}}" style="color:#470A68;text-decoration:underline;">Unsubscribe</a>
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
```

## Usage rules
- Only replace `{{BODY_HTML}}` with generated body content.
- Do not change any colors, padding, fonts, widths, or structure.
- Body content must follow the design system (palette, typography, CTA buttons).
