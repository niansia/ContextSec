export async function connectSlack(slackOauthClient: SlackOauthClient) {
  return slackOauthClient.exchange({ refresh_token, scopes });
}
