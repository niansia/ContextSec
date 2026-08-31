export async function POST(request: Request) {
  return startSupportSession(await request.json());
}
