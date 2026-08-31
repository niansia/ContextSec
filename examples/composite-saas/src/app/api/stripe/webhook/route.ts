import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const rawBody = await request.text();
  const event = stripe.webhooks.constructEvent(
    rawBody,
    request.headers.get("stripe-signature")!,
    process.env.STRIPE_WEBHOOK_SECRET!,
  );
  return Response.json({ acceptedType: event.type });
}
