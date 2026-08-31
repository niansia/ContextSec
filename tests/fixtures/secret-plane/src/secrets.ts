import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";

const client = new SecretsManagerClient({});
export const loadCredential = (secretId: string) =>
  client.send(new GetSecretValueCommand({ SecretId: secretId }));
