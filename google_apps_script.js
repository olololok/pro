
function doGet(e) {
    // 1. LOCK: Prevent race conditions so two VMs don't get the same number at once
    var lock = LockService.getScriptLock();
    try {
        lock.waitLock(10000); // Wait up to 10 seconds
    } catch (e) {
        return ContentService.createTextOutput("Server busy, try again").setMimeType(ContentService.MimeType.TEXT);
    }

    // 2. COUNTER: Get current counter, increment, and save
    var props = PropertiesService.getScriptProperties();
    var currentCount = Number(props.getProperty('COUNTER')) || 0;
    var nextCount = currentCount + 1;
    props.setProperty('COUNTER', nextCount.toString());

    // Release lock immediately after updating counter
    lock.releaseLock();

    // 3. CALC LIST ID: Map 1..infinity to 1..10
    // (nextCount - 1) % 10 + 1 ensures the sequence is 1, 2, ... 10, 1, 2...
    var listId = ((nextCount - 1) % 5) + 1;

    // 4. CACHE: Check if we have this list in cache
    var cache = CacheService.getScriptCache();
    var cacheKey = "proxy_list_" + listId;
    var cachedContent = cache.get(cacheKey);

    if (cachedContent) {
        // Return cached
        return ContentService.createTextOutput(cachedContent).setMimeType(ContentService.MimeType.TEXT);
    }

    // 5. FETCH: Download from GitHub
    var url = "https://raw.githubusercontent.com/olololok/pro/main/proxy_lists/list_" + listId + ".txt";
    try {
        var response = UrlFetchApp.fetch(url);
        var content = response.getContentText();

        // 6. SAVE CACHE: Store for 25 minutes (max for GAS is usually 6 hours, safe to use 25 min)
        // We use 1500 seconds
        if (response.getResponseCode() === 200) {
            cache.put(cacheKey, content, 1800);
        }

        return ContentService.createTextOutput(content).setMimeType(ContentService.MimeType.TEXT);

    } catch (err) {
        return ContentService.createTextOutput("Error fetching list: " + err.toString()).setMimeType(ContentService.MimeType.TEXT);
    }
}
