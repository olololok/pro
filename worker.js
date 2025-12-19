export default {
    async fetch(request, env, ctx) {
        const TARGET_URL = "https://raw.githubusercontent.com/olololok/pro/main/proxy_lists/list_1.txt";
        const cacheUrl = new URL(request.url);
        const cacheKey = new Request(cacheUrl.toString(), request);
        const cache = caches.default;

        let response = await cache.match(cacheKey);

        if (!response) {
            console.log("Cache miss. Fetching from GitHub...");

            response = await fetch(TARGET_URL, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
            });

            response = new Response(response.body, response);
            response.headers.set("Cache-Control", "public, max-age=1800");
            response.headers.set("Access-Control-Allow-Origin", "*");

            ctx.waitUntil(cache.put(cacheKey, response.clone()));
        } else {
            console.log("Cache hit!");
        }

        return response;
    },
};
