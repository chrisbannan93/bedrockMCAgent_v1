# Example EDM (Service notice outage update)

**comm_type:** service_notice
**campaign_type:** outage
**product:** internet
**audience_stage:** active
**date_sent:** 2026-04-05
**source:** approved template example (HTML)

## HTML (use exactly as shown)

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
            <h1 style="margin:0 0 16px 0;font-family:Arial,Helvetica,sans-serif;font-size:26px;line-height:32px;color:#470A68;">Service update: outage resolved</h1>
            <p style="margin:0 0 16px 0;">Hey &lt;FIRSTNAME&gt;</p>
            <p style="margin:0 0 16px 0;">The outage affecting your area has been resolved and services are back online.</p>
            <p style="margin:0 0 24px 0;">If you’re still offline, restart your modem and check the lights are solid. If the issue continues, contact us below.</p>
            <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 24px 0;">
              <tr>
                <td align="left">
                  <a href="https://www.dodo.com/support" style="background:#0EE2B9;border:1px solid #0EE2B9;border-radius:3px;color:#353947;display:inline-block;font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:bold;line-height:13px;text-align:center;text-decoration:none;padding:13px 55px;">Get Support</a>
                </td>
              </tr>
            </table>
            <p style="margin:0;">Thanks for your patience, and sorry for the disruption.</p>
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
