const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Transform } = require('stream');

class HTTPClient {
    constructor(config) {
        this.config = config || {};
        this.instance = axios.create({
            timeout: this.config.timeout || 30000,
            maxRedirects: this.config.maxRedirects || 10,
            headers: {
                'User-Agent': this.config.userAgent || 'CLOBES-PRO/4.0.0',
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate'
            }
        });
    }

    // GET request
    async get(url, options = {}) {
        try {
            const startTime = Date.now();
            const response = await this.instance.get(url, options);
            const endTime = Date.now();
            
            return {
                data: response.data,
                status: response.status,
                headers: response.headers,
                time: endTime - startTime,
                size: JSON.stringify(response.data).length
            };
        } catch (error) {
            throw new Error(`HTTP GET failed: ${error.message}`);
        }
    }

    // POST request
    async post(url, data, options = {}) {
        try {
            const startTime = Date.now();
            const response = await this.instance.post(url, data, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });
            const endTime = Date.now();
            
            return {
                data: response.data,
                status: response.status,
                headers: response.headers,
                time: endTime - startTime,
                size: JSON.stringify(response.data).length
            };
        } catch (error) {
            throw new Error(`HTTP POST failed: ${error.message}`);
        }
    }

    // Download file with progress
    async download(url, outputPath, onProgress = null) {
        return new Promise((resolve, reject) => {
            axios({
                method: 'GET',
                url: url,
                responseType: 'stream'
            }).then(response => {
                const totalSize = parseInt(response.headers['content-length'], 10);
                let downloadedSize = 0;
                const startTime = Date.now();
                
                const writer = fs.createWriteStream(outputPath);
                
                response.data.on('data', (chunk) => {
                    downloadedSize += chunk.length;
                    if (onProgress && totalSize) {
                        const percent = (downloadedSize / totalSize * 100).toFixed(2);
                        const speed = downloadedSize / ((Date.now() - startTime) / 1000);
                        onProgress(percent, downloadedSize, totalSize, speed);
                    }
                });
                
                response.data.pipe(writer);
                
                writer.on('finish', () => {
                    const endTime = Date.now();
                    resolve({
                        path: outputPath,
                        size: downloadedSize,
                        time: endTime - startTime,
                        success: true
                    });
                });
                
                writer.on('error', reject);
            }).catch(reject);
        });
    }

    // Batch requests
    async batch(requests, concurrent = 5) {
        const results = [];
        for (let i = 0; i < requests.length; i += concurrent) {
            const batch = requests.slice(i, i + concurrent);
            const batchResults = await Promise.allSettled(
                batch.map(req => this.get(req.url, req.options))
            );
            results.push(...batchResults);
        }
        return results;
    }

    // Benchmark
    async benchmark(url, requests = 100, concurrent = 10) {
        console.log(`Benchmarking ${url} with ${requests} requests...`);
        
        const times = [];
        const errors = [];
        const startTime = Date.now();
        
        for (let i = 0; i < requests; i += concurrent) {
            const batch = [];
            for (let j = 0; j < concurrent && (i + j) < requests; j++) {
                batch.push(this.get(url).catch(error => ({ error })));
            }
            
            const results = await Promise.all(batch);
            results.forEach(result => {
                if (result.error) {
                    errors.push(result.error);
                } else if (result.time) {
                    times.push(result.time);
                }
            });
        }
        
        const endTime = Date.now();
        const totalTime = endTime - startTime;
        
        return {
            totalRequests: requests,
            successful: times.length,
            failed: errors.length,
            totalTime: totalTime,
            avgTime: times.reduce((a, b) => a + b, 0) / times.length || 0,
            minTime: Math.min(...times),
            maxTime: Math.max(...times),
            requestsPerSecond: (times.length / totalTime) * 1000
        };
    }
}

// Create default instance
const defaultClient = new HTTPClient();

module.exports = {
    HTTPClient,
    get: (url, options) => defaultClient.get(url, options),
    post: (url, data, options) => defaultClient.post(url, data, options),
    download: (url, outputPath, onProgress) => defaultClient.download(url, outputPath, onProgress),
    benchmark: (url, requests, concurrent) => defaultClient.benchmark(url, requests, concurrent)
};
