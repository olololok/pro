// BUT better to cache the GitHub response globally for that listNum.
// Let's use a custom key for the list to share cache across users assigned to the same list.
const cacheKey = new Request(`https://worker-internal/list_${listNum}`);
const cache = caches.default;

// Try to find the valid response in Cloudflare cache
let response = await cache.match(cacheKey);

if (!response) {
    console.log(`Cache miss for: ${targetUrl}`);

    // Fetch from GitHub
    const upstreamResponse = await fetch(targetUrl, {
        headers: {
            'User-Agent': 'Cloudflare-Worker-Proxy-Fetcher'
        }
    });

    // Prepare response for caching
    response = new Response(upstreamResponse.body, upstreamResponse);

    // key: only cache if successful
    if (response.status === 200) {
        // Cache for 30 minutes (1800 seconds)
        response.headers.set('Cache-Control', 'public, max-age=1800');

        // Put into cache
        ctx.waitUntil(cache.put(cacheKey, response.clone()));
    }
}

return response;
    },
};
