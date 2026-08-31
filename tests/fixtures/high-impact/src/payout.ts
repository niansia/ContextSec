export async function createPayout(amount: number) {
  return stripe.payouts.create({ amount });
}
