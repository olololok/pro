// Google Apps Script Proxy Sharder
// 1. Downloads a proxy file with retries and browser headers.
// 2. Splits the file into 40 parts.
// 3. Serves one part per request (Round Robin).

// CONFIGURATION
// Replace this with the raw URL of your BIG proxy list.
const PROXY_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/2.txt";
const TOTAL_PARTS = 40;

function doGet(e) {
    try {
        var cache = CacheService.getScriptCache();
        var cachedContent = cache.get("PROXY_LIST_V1");
        var content;

        if (cachedContent != null) {
            content = cachedContent;
        } else {
            // 1. Fetch content from source
            content = fetchWithRetries(PROXY_SOURCE_URL);
            if (!content || content.length === 0) {
                return ContentService.createTextOutput("Error: Failed to download proxy list or list is empty.");
            }
            // Cache for 30 minutes (1800 seconds)
            try {
                cache.put("PROXY_LIST_V1", content, 1800);
            } catch (e) {
                // If content is too big for cache (100KB limit), we just don't cache it
                // Or we could split it, but for now simple fallback
            }
        }

        // 2. Parse lines and strip comments
        var lines = content.split('\n').map(function (l) {
            return l.split('#')[0].trim(); // Remove comments starting with #
        }).filter(function (l) {
            return l.length > 5; // Minimal filter for empty lines
        });

        if (lines.length === 0) {
            return ContentService.createTextOutput("");
        }

        // 3. Calculate Chunks
        var chunkSize = Math.ceil(lines.length / TOTAL_PARTS);

        // 4. Get Current Part Index (Round Robin with Lock)
        var scriptProperties = PropertiesService.getScriptProperties();
        var lock = LockService.getScriptLock();

        // Attempt to get lock to safely increment counter
        var hasLock = lock.tryLock(10000); // wait up to 10s
        if (!hasLock) {
            // Fallback if lock fails: just pick random
            var index = Math.floor(Math.random() * TOTAL_PARTS);
        } else {
            var storedIndex = scriptProperties.getProperty('LAST_INDEX');
            var index = 0;
            if (storedIndex !== null) {
                index = parseInt(storedIndex, 10);
                index = (index + 1) % TOTAL_PARTS;
            }
            scriptProperties.setProperty('LAST_INDEX', index.toString());
            lock.releaseLock();
        }

        // 5. Slice the chunk
        var start = index * chunkSize;
        var end = Math.min(start + chunkSize, lines.length);
        var chunk = lines.slice(start, end);

        var output = chunk.join('\n');

        // 6. Return response
        return ContentService.createTextOutput(output);

    } catch (err) {
        return ContentService.createTextOutput("Error: " + err.toString());
    }
}

function fetchWithRetries(url) {
    var maxRetries = 3;
    var attempt = 0;

    while (attempt < maxRetries) {
        attempt++;
        try {
            var params = {
                'method': 'get',
                'muteHttpExceptions': true,
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/plain,application/json,text/html,*/*',
                    'Cache-Control': 'no-cache'
                }
            };

            var response = UrlFetchApp.fetch(url, params);
            var code = response.getResponseCode();

            if (code === 200) {
                return response.getContentText();
            }
            // If 429 or 5xx, wait and retry
            Utilities.sleep(1000 * attempt);

        } catch (e) {
            // Network error, wait and retry
            Utilities.sleep(1000 * attempt);
        }
    }
    return null; // Failed after retries
}
