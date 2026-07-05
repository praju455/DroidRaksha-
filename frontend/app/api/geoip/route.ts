import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  try {
    const { ips } = await req.json();
    if (!ips || !Array.isArray(ips)) {
      return NextResponse.json({ error: "Missing or invalid ips array" }, { status: 400 });
    }

    if (ips.length === 0) {
      return NextResponse.json([]);
    }

    // Free tier of ip-api supports batch endpoints (max 100 IPs per request)
    const response = await fetch("http://ip-api.com/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(ips)
    });

    if (!response.ok) {
      return NextResponse.json({ error: "Failed to fetch from ip-api" }, { status: response.status });
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error("GeoIP Error:", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}
