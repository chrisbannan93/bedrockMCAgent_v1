# Dodo EDM HTML: invalid vs approved (do not deviate)

Use this as a strict contrast reference. The **invalid** patterns below must never be generated. Use the **approved** patterns only.

## Invalid patterns (do not use)
- Non-approved colors (e.g., #006699, #ff6600)
- Random font sizes or font stacks
- Non-table layouts or missing 600px container
- CTA buttons without approved styles
- Missing Dodo logo header or legal footer

### Invalid example (forbidden)
```html
<table width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,sans-serif;font-size:14px;line-height:20px;color:#333333">
  <tr>
    <td style="padding:20px 10px">
      <h1 style="font-size:24px;line-height:32px;color:#006699;font-weight:bold;margin:0">Hey&nbsp;<span style="color:#006699">Firstname</span></h1>
      <p style="font-size:16px;line-height:24px;color:#333333;margin:10px 0">This summer, enjoy superfast internet at a super low price with Dodo's hot 50% off deal!</p>
      <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f6f6f6;border-radius:4px;margin-top:20px;padding:10px">
        <tr>
          <td style="padding:10px;text-align:center">
            <a href="#" style="background-color:#ff6600;color:#ffffff;border-radius:4px;padding:10px 20px;text-decoration:none;font-weight:bold">Get 50% Off Now!</a>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
```

## Approved patterns (must use)
- Use the fixed container shell and only replace `{{BODY_HTML}}`.
- Use approved colors and typography from the design system.
- Use the exact CTA HTML snippet for primary/secondary buttons.
- Always include the logo header and legal footer placeholders.

### Approved example (use this)
```html
<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="min-width:100%;background:#E0E0E5;">
  <tr>
    <td align="center" style="padding:0;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="600" style="width:100%;max-width:600px;background:#FFFFFF;">
        <tr>
          <td style="padding:20px 30px;background:#FFFFFF;">
            <img src="https://image.email.dodo.com/lib/fe2711717d64047d7d1d79/m/1/4d591d48-bf10-4af5-ae8c-d4a2d33abada.jpg" width="140" alt="Dodo" style="display:block;border:0;outline:none;text-decoration:none;height:auto;" />
          </td>
        </tr>
        <tr>
          <td style="padding:24px 30px;font-family:Arial,Helvetica,sans-serif;color:#353947;font-size:16px;line-height:24px;">
            <h1 style="margin:0 0 16px 0;font-family:Arial,Helvetica,sans-serif;font-size:26px;line-height:32px;color:#470A68;">Dodo summer offer</h1>
            <p style="margin:0 0 16px 0;">Hi &lt;FIRSTNAME&gt;, enjoy superfast internet at a Dodo-approved rate.</p>
            <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 24px 0;">
              <tr>
                <td align="left">
                  <a href="{{CTA_URL}}" style="background:#0EE2B9;border:1px solid #0EE2B9;border-radius:3px;color:#353947;display:inline-block;font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:bold;line-height:13px;text-align:center;text-decoration:none;padding:13px 55px;">{{CTA_LABEL}}</a>
                </td>
              </tr>
            </table>
            <p style="margin:0;">Need help? <a href="{{SUPPORT_URL}}" style="color:#470A68;text-decoration:underline;">Visit support</a>.</p>
          </td>
        </tr>
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
