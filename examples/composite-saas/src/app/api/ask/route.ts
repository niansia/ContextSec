import OpenAI from "openai";
import { prisma } from "@/lib/prisma";

const openai = new OpenAI();

export async function POST(request: Request) {
  const { invoiceId } = await request.json();
  const invoice = await prisma.invoice.findUnique({ where: { id: invoiceId } });
  console.log("invoice for assistant", invoice);
  const response = await openai.responses.create({
    model: "gpt-example",
    input: JSON.stringify(invoice),
  });
  return Response.json({ answer: response.output_text });
}
