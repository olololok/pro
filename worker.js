export default {
    async fetch(request, env, ctx) {
        // Configuration
        // Using the newly created general list
        const SOURCE_URL = "https://raw.githubusercontent.com/olololok/pro/main/proxy_list_found.txt";
        const CACHE_TTL = 1800; // 30 minutes in seconds
        const LIST_COUNT = 10;

        // Use a synthetic key to cache the UPSTREAM content (the full list)
        // This ensures we only hit GitHub once every 30 mins, but can process data differently per request.
        const cache = caches.default;
        const sourceCacheKey = new Request("https://worker-internal/proxy-source-data");

        let response = await cache.match(sourceCacheKey);
        let proxyData = "";

        if (!response) {
            console.log("Cache miss. Fetching from GitHub...");

            // Fetch from GitHub
            const upstreamResponse = await fetch(SOURCE_URL, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
            });

            if (!upstreamResponse.ok) {
                return new Response("Failed to fetch proxies from source", { status: 502 });
            }

            proxyData = await upstreamResponse.text();

            // Create a cacheable response for the source data
            // We must create a new Response object to store in cache with correct headers
            const cachedResponse = new Response(proxyData, {
                headers: {
                    "Cache-Control": `public, max-age=${CACHE_TTL}`,
                    "Content-Type": "text/plain"
                }
            });

            // Store in cache
            ctx.waitUntil(cache.put(sourceCacheKey, cachedResponse.clone()));
        } else {
            console.log("Cache hit! Serving from local cache.");
            proxyData = await response.text();
        }

        // Processing Logic
        // 1. Split into lines and filter empty
        const lines = proxyData.split('\n').map(l => l.trim()).filter(l => l.length > 0);

        if (lines.length === 0) {
            return new Response("No proxies found", { status: 404 });
        }

        // 2. Divide into 10 lists (Round-robin distribution to ensure deterministic-ish splitting if needed, 
        //    or just pure random separation. User said "divides into 10 lists")
        //    Let's emulate the '10 files' logic.

        const lists = Array.from({ length: LIST_COUNT }, () => []);

        lines.forEach((line, index) => {
            lists[index % LIST_COUNT].push(line);
        });

        // 3. Randomly give back ONE of the lists
        const randomIndex = Math.floor(Math.random() * LIST_COUNT);
        const selectedList = lists[randomIndex];
        const resultText = selectedList.join('\n');

        return new Response(resultText, {
            headers: {
                "Content-Type": "text/plain",
                "Access-Control-Allow-Origin": "*",
                // Do NOT cache the final response heavily, so the user gets a random list on reload
                // But maybe small cache (5s) to prevent abuse? Let's say no-cache for now to prove randomness.
                "Cache-Control": "no-store",
                "X-List-Index": String(randomIndex + 1),
                "X-Total-Proxies": String(lines.length),
                "X-List-Size": String(selectedList.length)
            }
        });
    },
};
