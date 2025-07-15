// server.js
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const whois = require('whois');
const dns = require('dns').promises;
const axios = require('axios');
const geoip = require('geoip-lite');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Cache setup - optimized for Railway
const cache = new NodeCache({ 
  stdTTL: 86400, // 24 hours default
  checkperiod: 3600, // cleanup every hour
  maxKeys: 1000 // limit memory usage
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // requests per window
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    cache: { keys: cache.keys().length }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Main analysis endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    
    const cleanDomain = cleanDomainName(domain);
    console.log(`Analyzing: ${cleanDomain}`);
    
    const cacheKey = `analysis:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    
    if (cached) {
      return res.json({ ...cached, fromCache: true });
    }
    
    const analysis = await performQuickAnalysis(cleanDomain);
    cache.set(cacheKey, analysis, 21600); // 6 hours
    
    res.json(analysis);
    
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ 
      error: error.message,
      domain: req.body.domain 
    });
  }
});

// Bulk analysis endpoint
app.post('/api/bulk-analyze', async (req, res) => {
  try {
    const { domains } = req.body;
    
    if (!domains || !Array.isArray(domains)) {
      return res.status(400).json({ error: 'Domains array is required' });
    }
    
    if (domains.length > 10) {
      return res.status(400).json({ error: 'Maximum 10 domains per request' });
    }
    
    const results = [];
    
    for (const domain of domains) {
      try {
        const cleanDomain = cleanDomainName(domain);
        const cacheKey = `analysis:${cleanDomain}`;
        
        let analysis = cache.get(cacheKey);
        
        if (!analysis) {
          analysis = await performQuickAnalysis(cleanDomain);
          cache.set(cacheKey, analysis, 21600);
        }
        
        results.push(analysis);
        await new Promise(resolve => setTimeout(resolve, 800));
        
      } catch (error) {
        results.push({
          domain: domain,
          error: error.message,
          success: false,
          timestamp: new Date().toISOString()
        });
      }
    }
    
    res.json({ results, total: results.length });
    
  } catch (error) {
    console.error('Bulk analysis error:', error);
    res.status(500).json({ error: error.message });
  }
});

async function performQuickAnalysis(domain) {
  const startTime = Date.now();
  
  const analysis = {
    domain,
    timestamp: new Date().toISOString(),
    success: true,
    processingTime: null,
    whoisData: null,
    dnsData: null,
    privacyAnalysis: null,
    registrarInfo: null,
    geoData: null,
    summary: {}
  };
  
  try {
    // WHOIS Lookup with timeout
    analysis.whoisData = await Promise.race([
      getWhoisData(domain),
      new Promise((_, reject) => setTimeout(() => reject(new Error('WHOIS timeout')), 15000))
    ]);
    
    // DNS Records with timeout
    analysis.dnsData = await Promise.race([
      getDNSRecords(domain),
      new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), 10000))
    ]);
    
    // Fast analysis
    analysis.privacyAnalysis = analyzePrivacyProtection(analysis.whoisData);
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    
    // Privacy domain analysis (optional)
    if (analysis.privacyAnalysis.isPrivate && analysis.privacyAnalysis.privacyDomain) {
      try {
        const privacyWhois = await Promise.race([
          getWhoisData(analysis.privacyAnalysis.privacyDomain),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Privacy timeout')), 10000))
        ]);
        analysis.privacyAnalysis.privacyDomainWhois = privacyWhois;
      } catch (error) {
        console.log(`Privacy domain analysis failed: ${error.message}`);
      }
    }
    
    analysis.summary = generateSummary(analysis);
    analysis.processingTime = Date.now() - startTime;
    
  } catch (error) {
    analysis.success = false;
    analysis.error = error.message;
    analysis.processingTime = Date.now() - startTime;
  }
  
  return analysis;
}

async function getWhoisData(domain) {
  // Try command line whois first
  try {
    const result = await whoisCommandLookup(domain);
    if (result) return result;
  } catch (error) {
    console.log(`Command WHOIS failed: ${error.message}`);
  }
  
  // Fallback to API
  try {
    const result = await whoisAPILookup(domain);
    if (result) return result;
  } catch (error) {
    console.log(`API WHOIS failed: ${error.message}`);
  }
  
  throw new Error(`All WHOIS methods failed for ${domain}`);
}

async function whoisAPILookup(domain) {
  try {
    const response = await axios.get(`https://whoisjson.com/api/v1/whois?domain=${domain}`, {
      timeout: 8000,
      headers: { 
        'User-Agent': 'WHOIS-Railway-Tool/1.0',
        ...(process.env.WHOISJSON_API_KEY && { 'Authorization': `Bearer ${process.env.WHOISJSON_API_KEY}` })
      }
    });
    
    if (response.data && !response.data.error) {
      return parseWhoisResponse(response.data);
    }
  } catch (error) {
    console.log('WhoisJSON API failed');
  }
  
  return null;
}

function whoisCommandLookup(domain) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('WHOIS command timeout'));
    }, 12000);
    
    whois.lookup(domain, { timeout: 10000 }, (err, data) => {
      clearTimeout(timeout);
      if (err) {
        reject(err);
      } else {
        resolve(parseRawWhois(data, domain));
      }
    });
  });
}

async function getDNSRecords(domain) {
  const records = {};
  const startTime = Date.now();
  
  const dnsPromises = [
    dns.resolve4(domain).catch(() => []),
    dns.resolve6(domain).catch(() => []),
    dns.resolveMx(domain).catch(() => []),
    dns.resolveNs(domain).catch(() => []),
    dns.resolveTxt(domain).catch(() => []),
    dns.resolveSoa(domain).catch(() => null)
  ];
  
  const [A, AAAA, MX, NS, TXT, SOA] = await Promise.all(dnsPromises);
  
  records.A = A;
  records.AAAA = AAAA;
  records.MX = MX;
  records.NS = NS;
  records.TXT = TXT;
  records.SOA = SOA;
  records.queryTime = Date.now() - startTime;
  
  return records;
}

function analyzePrivacyProtection(whoisData) {
  const privacyServices = [
    'whoisguard', 'domains by proxy', 'perfect privacy', 'private whois',
    'contact privacy', 'redacted for privacy', 'data protected',
    'privacy service', 'whois privacy', 'private registration'
  ];
  
  const whoisText = JSON.stringify(whoisData).toLowerCase();
  
  let isPrivate = false;
  let privacyService = null;
  let privacyDomain = null;
  
  for (const service of privacyServices) {
    if (whoisText.includes(service)) {
      isPrivate = true;
      privacyService = service;
      break;
    }
  }
  
  if (isPrivate && whoisData.emails) {
    for (const email of whoisData.emails) {
      const domain = email.split('@')[1];
      if (domain && (domain.includes('privacy') || domain.includes('whoisguard') || domain.includes('proxy'))) {
        privacyDomain = domain;
        break;
      }
    }
  }
  
  return { isPrivate, privacyService, privacyDomain };
}

function analyzeRegistrar(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  let category = 'Other';
  let isUSBased = false;
  
  const registrarLower = registrar.toLowerCase();
  
  if (registrarLower.includes('godaddy')) {
    category = 'Major US Commercial';
    isUSBased = true;
  } else if (registrarLower.includes('namecheap')) {
    category = 'Discount US Provider';
    isUSBased = true;
  } else if (registrarLower.includes('network solutions') || registrarLower.includes('verisign')) {
    category = 'Legacy US Provider';
    isUSBased = true;
  }
  
  return {
    name: registrar,
    category,
    isUSBased,
    country: whoisData.registrantCountry || 'Unknown'
  };
}

async function analyzeGeolocation(dnsData) {
  const geoInfo = { countries: new Set(), primaryLocation: null };
  
  if (dnsData.A && dnsData.A.length > 0) {
    for (const ip of dnsData.A.slice(0, 3)) {
      const geo = geoip.lookup(ip);
      if (geo) {
        geoInfo.countries.add(geo.country);
        if (!geoInfo.primaryLocation) {
          geoInfo.primaryLocation = {
            ip, country: geo.country, region: geo.region, city: geo.city
          };
        }
      }
    }
  }
  
  return {
    countries: Array.from(geoInfo.countries),
    primaryLocation: geoInfo.primaryLocation,
    totalIPs: dnsData.A ? dnsData.A.length : 0
  };
}

function generateSummary(analysis) {
  const flags = [];
  
  if (analysis.registrarInfo?.isUSBased) flags.push('US_REGISTRAR');
  if (analysis.privacyAnalysis?.isPrivate) flags.push('PRIVACY_PROTECTED');
  if (analysis.privacyAnalysis?.privacyDomain) flags.push('CHECK_PRIVACY_DOMAIN');
  if (analysis.geoData?.primaryLocation?.country === 'US') flags.push('US_HOSTED');
  
  return {
    domain: analysis.domain,
    isUSRegistrar: analysis.registrarInfo?.isUSBased || false,
    registrar: analysis.registrarInfo?.name || 'Unknown',
    isPrivacyProtected: analysis.privacyAnalysis?.isPrivate || false,
    privacyDomain: analysis.privacyAnalysis?.privacyDomain || null,
    registrantCountry: analysis.whoisData?.registrantCountry || 'Unknown',
    creationDate: analysis.whoisData?.creationDate || 'Unknown',
    expirationDate: analysis.whoisData?.expirationDate || 'Unknown',
    nameServers: analysis.dnsData?.NS || [],
    primaryIP: analysis.dnsData?.A?.[0] || null,
    geoLocation: analysis.geoData?.primaryLocation || null,
    quickAssessment: {
      flags,
      priority: flags.includes('CHECK_PRIVACY_DOMAIN') ? 'high' : 'normal',
      recommendation: flags.includes('CHECK_PRIVACY_DOMAIN') ? 
        'Check privacy contact domain for actual registrant details' :
        flags.includes('PRIVACY_PROTECTED') ? 
        'Domain uses privacy protection - limited public info' :
        flags.includes('US_REGISTRAR') ? 
        'US-based registrar - UDRP procedures available' :
        'Standard domain registration'
    }
  };
}

function cleanDomainName(domain) {
  return domain.trim()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .toLowerCase();
}

function parseWhoisResponse(data) {
  return {
    domain: data.domain,
    registrar: data.registrar,
    creationDate: data.creation_date || data.created,
    expirationDate: data.expiration_date || data.expires,
    registrantCountry: data.registrant_country,
    emails: extractEmails(JSON.stringify(data))
  };
}

function parseRawWhois(rawData, domain) {
  const lines = rawData.split('\n');
  const parsed = { domain, rawData };
  
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (lower.includes('registrar:')) {
      parsed.registrar = line.split(':')[1]?.trim();
    } else if (lower.includes('creation date:') || lower.includes('created:')) {
      parsed.creationDate = line.split(':')[1]?.trim();
    } else if (lower.includes('registrant country:')) {
      parsed.registrantCountry = line.split(':')[1]?.trim();
    }
  }
  
  parsed.emails = extractEmails(rawData);
  return parsed;
}

function extractEmails(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = text.match(emailRegex) || [];
  return [...new Set(emails)];
}

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 WHOIS Backend Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

module.exports = app;