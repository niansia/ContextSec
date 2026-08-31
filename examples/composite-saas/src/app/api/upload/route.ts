import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

const s3 = new S3Client({});

export async function POST(request: Request) {
  const form = await request.formData();
  const file = form.get("file") as File;
  await s3.send(new PutObjectCommand({
    Bucket: process.env.UPLOAD_BUCKET!,
    Key: file.name,
    Body: Buffer.from(await file.arrayBuffer()),
    ContentType: file.type,
    ACL: "public-read",
  }));
  return Response.json({ ok: true });
}
