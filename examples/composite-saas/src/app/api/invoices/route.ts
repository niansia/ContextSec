import { prisma } from "@/lib/prisma";

export async function GET(request: Request) {
  const invoiceId = new URL(request.url).searchParams.get("id")!;
  const invoice = await prisma.invoice.findUnique({ where: { id: invoiceId } });
  return Response.json(invoice);
}
