const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class CacheEntry {
    constructor(key, value, ttl = 300000) { // 5 minutes default
        this.key = key;
        this.value = value;
        this.timestamp = Date.now();
        this.expires = this.timestamp + ttl;
        this.hits = 0;
    }

    isExpired() {
        return Date.now() > this.expires;
    }

    hit() {
        this.hits++;
        return this.value;
    }
}

class Cache {
    constructor(options = {}) {
        this.options = {
            maxSize: options.maxSize || 100,
            defaultTTL: options.defaultTTL || 300000,
            enabled: options.enabled !== false
        };
        this.cache = new Map();
        this.hits = 0;
        this.misses = 0;
        this.stats = {
            totalSets: 0,
            totalGets: 0,
            totalEvictions: 0
        };
        
        // Start cleanup interval
        if (this.options.enabled) {
            this.cleanupInterval = setInterval(() => this.cleanup(), 60000); // Clean every minute
        }
    }

    // Generate cache key from arguments
    generateKey(...args) {
        const str = JSON.stringify(args);
        return crypto.createHash('md5').update(str).digest('hex');
    }

    // Set cache entry
    set(key, value, ttl = null) {
        if (!this.options.enabled) return;
        
        // Evict if cache is full
        if (this.cache.size >= this.options.maxSize) {
            this.evict();
        }
        
        const entry = new CacheEntry(key, value, ttl || this.options.defaultTTL);
        this.cache.set(key, entry);
        this.stats.totalSets++;
    }

    // Get cache entry
    get(key) {
        if (!this.options.enabled) return null;
        
        this.stats.totalGets++;
        
        const entry = this.cache.get(key);
        if (!entry) {
            this.misses++;
            return null;
        }
        
        if (entry.isExpired()) {
            this.cache.delete(key);
            this.misses++;
            return null;
        }
        
        this.hits++;
        return entry.hit();
    }

    // Delete cache entry
    delete(key) {
        this.cache.delete(key);
    }

    // Clear all cache
    clear() {
        this.cache.clear();
        this.hits = 0;
        this.misses = 0;
        this.stats = { totalSets: 0, totalGets: 0, totalEvictions: 0 };
    }

    // Evict expired or least used entries
    evict(count = 1) {
        const entries = Array.from(this.cache.entries());
        
        // First, remove expired entries
        const expired = entries.filter(([key, entry]) => entry.isExpired());
        expired.forEach(([key]) => this.cache.delete(key));
        
        // If still need to evict, remove least used
        if (this.cache.size >= this.options.maxSize) {
            const sorted = entries
                .filter(([key, entry]) => !entry.isExpired())
                .sort((a, b) => a[1].hits - b[1].hits)
                .slice(0, count);
            
            sorted.forEach(([key]) => this.cache.delete(key));
            this.stats.totalEvictions += sorted.length;
        }
    }

    // Cleanup expired entries
    cleanup() {
        let cleaned = 0;
        for (const [key, entry] of this.cache.entries()) {
            if (entry.isExpired()) {
                this.cache.delete(key);
                cleaned++;
            }
        }
        if (cleaned > 0) {
            console.log(`Cache cleanup: removed ${cleaned} expired entries`);
        }
    }

    // Get cache stats
    getStats() {
        const hitRate = this.hits + this.misses > 0 
            ? (this.hits / (this.hits + this.misses) * 100).toFixed(2)
            : 0;
        
        return {
            size: this.cache.size,
            hits: this.hits,
            misses: this.misses,
            hitRate: `${hitRate}%`,
            maxSize: this.options.maxSize,
            enabled: this.options.enabled,
            ...this.stats
        };
    }

    // Persist cache to disk
    persist(filePath) {
        if (!this.options.enabled) return;
        
        const data = {
            entries: Array.from(this.cache.entries()).map(([key, entry]) => ({
                key,
                value: entry.value,
                timestamp: entry.timestamp,
                expires: entry.expires,
                hits: entry.hits
            })),
            stats: {
                hits: this.hits,
                misses: this.misses,
                ...this.stats
            }
        };
        
        try {
            fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
            return true;
        } catch (error) {
            console.error('Failed to persist cache:', error);
            return false;
        }
    }

    // Load cache from disk
    load(filePath) {
        if (!this.options.enabled) return false;
        
        try {
            if (fs.existsSync(filePath)) {
                const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                
                this.cache.clear();
                data.entries.forEach(item => {
                    const entry = new CacheEntry(item.key, item.value);
                    entry.timestamp = item.timestamp;
                    entry.expires = item.expires;
                    entry.hits = item.hits;
                    this.cache.set(item.key, entry);
                });
                
                this.hits = data.stats.hits || 0;
                this.misses = data.stats.misses || 0;
                this.stats = data.stats;
                
                return true;
            }
        } catch (error) {
            console.error('Failed to load cache:', error);
        }
        return false;
    }

    // Cleanup on exit
    destroy() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.clear();
    }
}

// Create default cache instance
const defaultCache = new Cache();

module.exports = {
    Cache,
    cache: defaultCache
};
