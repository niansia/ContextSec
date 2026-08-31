export async function createCharge(body: URLSearchParams) {
  return fetch("https://api.stripe.com/v1/payment_intents", {
    method: "POST",
    body,
  });
}
