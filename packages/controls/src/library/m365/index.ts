import type { ControlDefinition } from '../../define.js';
import { m365MailboxAuditing, m365UnifiedAuditLog } from './audit.js';
import { m365SafeAttachmentsSpo } from './defender.js';
import {
  m365ModernAuthExchange,
  m365SmtpAuthDisabled,
  m365SmtpAuthMailboxes,
} from './exchange-auth.js';
import {
  m365MailboxExternalForwarding,
  m365OutboundSpamForwarding,
  m365RemoteDomainForwarding,
} from './forwarding.js';
import { m365DkimEnabled, m365DmarcPolicy, m365SpfPublished } from './mail-authentication.js';
import { m365SharePointAnyoneLinks, m365SharePointLegacyAuth } from './sharepoint.js';

export const M365_CONTROLS: readonly ControlDefinition[] = [
  m365UnifiedAuditLog,
  m365MailboxAuditing,
  m365SmtpAuthDisabled,
  m365SmtpAuthMailboxes,
  m365OutboundSpamForwarding,
  m365RemoteDomainForwarding,
  m365MailboxExternalForwarding,
  m365ModernAuthExchange,
  m365DkimEnabled,
  m365SpfPublished,
  m365DmarcPolicy,
  m365SharePointAnyoneLinks,
  m365SharePointLegacyAuth,
  m365SafeAttachmentsSpo,
];
