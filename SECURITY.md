# Security

Do not commit API tokens, signing secrets, payloads containing personal information, or private attachments. Use dedicated client keys and HTTPS outside isolated local QA. Report vulnerabilities privately through the NVL repository maintainer before publication. Callback routes require fresh signed raw bodies and configured client binding. Keep business authorization in the consuming application, and never select an API connection from untrusted request data.
