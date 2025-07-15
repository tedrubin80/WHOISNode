// server.js - Production WHOIS Backend
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const whois = require('whois');
const dns = require('dns').promises;
const axios = require('axios');
const geoip = require('geoip-lite');

const app = express();
const PORT = process.env.PORT || 3001;

// Cache setup - 24 hours for WHOIS, 1 hour for DNS
const cache = new NodeCache({ 
  stdTTL: 86400, // 24 hours default
  checkperiod: 3600 // cleanup every hour
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});

app.use(cors());
app.use(express.json());
app.use(limiter);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Main analysis endpoint - optimized for your workflow
app.post('/api/analyze', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    
    const cleanDomain = cleanDomainName(domain);
    console.log(`Analyzing: ${cleanDomain}`);
    
    // Check cache first
    const cacheKey = `analysis:${cleanDomain}`;
    const cached = cache.get(cacheKey);
    
    if (cached) {
      console.log(`Cache hit for: ${cleanDomain}`);
      return res.json({ ...cached, fromCache: true });
    }
    
    // Perform analysis
    const analysis = await performQuickAnalysis(cleanDomain);
    
    // Cache results
    cache.set(cacheKey, analysis, 86400); // 24 hours
    
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
    
    if (domains.length > 20) {
      return res.status(400).json({ error: 'Maximum 20 domains per request' });
    }
    
    const results = [];
    
    for (const domain of domains) {
      try {
        const cleanDomain = cleanDomainName(domain);
        const cacheKey = `analysis:${cleanDomain}`;
        
        let analysis = cache.get(cacheKey);
        
        if (!analysis) {
          analysis = await performQuickAnalysis(cleanDomain);
          cache.set(cacheKey, analysis, 86400);
        }
        
        results.push(analysis);
        
        // Rate limiting between requests
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (error) {
        results.push({
          domain: domain,
          error: error.message,
          success: false
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
    // 1. WHOIS Lookup
    console.log(`Getting WHOIS for: ${domain}`);
    analysis.whoisData = await getWhoisData(domain);
    
    // 2. DNS Records
    console.log(`Getting DNS for: ${domain}`);
    analysis.dnsData = await getDNSRecords(domain);
    
    // 3. Privacy Analysis (your key requirement)
    analysis.privacyAnalysis = analyzePrivacyProtection(analysis.whoisData);
    
    // 4. Registrar Analysis
    analysis.registrarInfo = analyzeRegistrar(analysis.whoisData);
    
    // 5. Geographic Analysis
    analysis.geoData = await analyzeGeolocation(analysis.dnsData);
    
    // 6. If privacy protected, analyze the privacy contact domain
    if (analysis.privacyAnalysis.isPrivate && analysis.privacyAnalysis.privacyDomain) {
      console.log(`Analyzing privacy domain: ${analysis.privacyAnalysis.privacyDomain}`);
      try {
        const privacyWhois = await getWhoisData(analysis.privacyAnalysis.privacyDomain);
        analysis.privacyAnalysis.privacyDomainWhois = privacyWhois;
      } catch (error) {
        console.log(`Privacy domain analysis failed: ${error.message}`);
      }
    }
    
    // 7. Generate Summary (your workflow focus)
    analysis.summary = generateSummary(analysis);
    
    analysis.processingTime = Date.now() - startTime;
    
  } catch (error) {
    analysis.success = false;
    analysis.error = error.message;
  }
  
  return analysis;
}

async function getWhoisData(domain) {
  // Try multiple WHOIS methods
  const methods = [
    () => whoisAPILookup(domain),
    () => whoisCommandLookup(domain)
  ];
  
  for (const method of methods) {
    try {
      const result = await method();
      if (result) return result;
    } catch (error) {
      console.log(`WHOIS method failed: ${error.message}`);
    }
  }
  
  throw new Error(`All WHOIS methods failed for ${domain}`);
}

async function whoisAPILookup(domain) {
  // Try whoisjson.com first (has free tier)
  try {
    const response = await axios.get(`https://whoisjson.com/api/v1/whois?domain=${domain}`, {
      timeout: 10000,
      headers: { 'User-Agent': 'WHOIS-Tool/1.0' }
    });
    
    if (response.data && !response.data.error) {
      return parseWhoisResponse(response.data);
    }
  } catch (error) {
    console.log('WhoisJSON API failed, trying command line...');
  }
  
  return null;
}

function whoisCommandLookup(domain) {
  return new Promise((resolve, reject) => {
    whois.lookup(domain, { timeout: 10000 }, (err, data) => {
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
  
  try {
    // A Records
    records.A = await dns.resolve4(domain);
  } catch (e) { records.A = []; }
  
  try {
    // AAAA Records  
    records.AAAA = await dns.resolve6(domain);
  } catch (e) { records.AAAA = []; }
  
  try {
    // MX Records
    records.MX = await dns.resolveMx(domain);
  } catch (e) { records.MX = []; }
  
  try {
    // NS Records
    records.NS = await dns.resolveNs(domain);
  } catch (e) { records.NS = []; }
  
  try {
    // TXT Records
    records.TXT = await dns.resolveTxt(domain);
  } catch (e) { records.TXT = []; }
  
  try {
    // SOA Record
    records.SOA = await dns.resolveSoa(domain);
  } catch (e) { records.SOA = null; }
  
  records.queryTime = Date.now() - startTime;
  return records;
}

function analyzePrivacyProtection(whoisData) {
  const privacyServices = [
    'whoisguard', 'domains by proxy', 'perfect privacy', 'private whois',
    'contact privacy', 'redacted for privacy', 'data protected',
    'privacy service', 'whois privacy', 'private registration',
    'godaddy.com', 'namecheap.com', 'tucows.com'
  ];
  
  const whoisText = JSON.stringify(whoisData).toLowerCase();
  
  let isPrivate = false;
  let privacyService = null;
  let privacyDomain = null;
  
  // Check for privacy indicators
  for (const service of privacyServices) {
    if (whoisText.includes(service)) {
      isPrivate = true;
      privacyService = service;
      break;
    }
  }
  
  // Extract privacy contact domain from emails
  if (isPrivate && whoisData.emails) {
    for (const email of whoisData.emails) {
      const domain = email.split('@')[1];
      if (domain && (
        domain.includes('privacy') || 
        domain.includes('whoisguard') || 
        domain.includes('proxy')
      )) {
        privacyDomain = domain;
        break;
      }
    }
  }
  
  return {
    isPrivate,
    privacyService,
    privacyDomain,
    confidence: isPrivate ? 'high' : 'low'
  };
}

function analyzeRegistrar(whoisData) {
  const registrar = whoisData.registrar || 'Unknown';
  
  // Categorize registrar
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
  } else if (registrarLower.includes('enom') || registrarLower.includes('tucows')) {
    category = 'US Wholesale/Reseller';
    isUSBased = true;
  }
  
  return {
    name: registrar,
    category,
    isUSBased,
    country: whoisData.registrantCountry || whoisData.adminCountry || 'Unknown'
  };
}

async function analyzeGeolocation(dnsData) {
  const geoInfo = {
    countries: new Set(),
    regions: new Set(),
    cities: new Set(),
    isps: new Set(),
    primaryLocation: null
  };
  
  // Analyze A records
  if (dnsData.A && dnsData.A.length > 0) {
    for (const ip of dnsData.A) {
      const geo = geoip.lookup(ip);
      if (geo) {
        geoInfo.countries.add(geo.country);
        geoInfo.regions.add(geo.region);
        geoInfo.cities.add(geo.city);
        
        if (!geoInfo.primaryLocation) {
          geoInfo.primaryLocation = {
            ip,
            country: geo.country,
            region: geo.region,
            city: geo.city,
            timezone: geo.timezone
          };
        }
      }
    }
  }
  
  return {
    countries: Array.from(geoInfo.countries),
    regions: Array.from(geoInfo.regions),
    cities: Array.from(geoInfo.cities),
    primaryLocation: geoInfo.primaryLocation,
    totalIPs: dnsData.A ? dnsData.A.length : 0
  };
}

function generateSummary(analysis) {
  const summary = {
    domain: analysis.domain,
    isUSRegistrar: analysis.registrarInfo?.isUSBased || false,
    registrar: analysis.registrarInfo?.name || 'Unknown',
    registrarCategory: analysis.registrarInfo?.category || 'Unknown',
    isPrivacyProtected: analysis.privacyAnalysis?.isPrivate || false,
    privacyService: analysis.privacyAnalysis?.privacyService || null,
    privacyDomain: analysis.privacyAnalysis?.privacyDomain || null,
    registrantCountry: analysis.whoisData?.registrantCountry || 'Unknown',
    creationDate: analysis.whoisData?.creationDate || 'Unknown',
    expirationDate: analysis.whoisData?.expirationDate || 'Unknown',
    nameServers: analysis.dnsData?.NS || [],
    primaryIP: analysis.dnsData?.A?.[0] || null,
    geoLocation: analysis.geoData?.primaryLocation || null,
    
    // Quick decision helpers for your workflow
    needsPrivacyDomainCheck: analysis.privacyAnalysis?.isPrivate && analysis.privacyAnalysis?.privacyDomain,
    quickAssessment: generateQuickAssessment(analysis)
  };
  
  return summary;
}

function generateQuickAssessment(analysis) {
  const flags = [];
  
  if (analysis.registrarInfo?.isUSBased) {
    flags.push('US_REGISTRAR');
  }
  
  if (analysis.privacyAnalysis?.isPrivate) {
    flags.push('PRIVACY_PROTECTED');
    if (analysis.privacyAnalysis?.privacyDomain) {
      flags.push('CHECK_PRIVACY_DOMAIN');
    }
  }
  
  if (analysis.geoData?.primaryLocation?.country === 'US') {
    flags.push('US_HOSTED');
  }
  
  return {
    flags,
    priority: flags.includes('CHECK_PRIVACY_DOMAIN') ? 'high' : 'normal',
    recommendation: generateRecommendation(flags)
  };
}

function generateRecommendation(flags) {
  if (flags.includes('CHECK_PRIVACY_DOMAIN')) {
    return 'Check privacy contact domain for actual registrant details';
  }
  if (flags.includes('PRIVACY_PROTECTED')) {
    return 'Domain uses privacy protection - limited public info';
  }
  if (flags.includes('US_REGISTRAR')) {
    return 'US-based registrar - UDRP procedures available';
  }
  return 'Standard domain registration';
}

// Utility functions
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
    updatedDate: data.updated_date || data.updated,
    status: data.status,
    registrantName: data.registrant_name,
    registrantOrganization: data.registrant_organization,
    registrantEmail: data.registrant_email,
    registrantCountry: data.registrant_country,
    adminEmail: data.admin_email,
    techEmail: data.tech_email,
    nameServers: data.name_servers || data.nameservers,
    emails: extractEmails(JSON.stringify(data)),
    rawData: data
  };
}

function parseRawWhois(rawData, domain) {
  const lines = rawData.split('\n');
  const parsed = { domain, rawData };
  
  // Extract key fields from raw WHOIS
  for (const line of lines) {
    const lower = line.toLowerCase();
    
    if (lower.includes('registrar:')) {
      parsed.registrar = line.split(':')[1]?.trim();
    } else if (lower.includes('creation date:') || lower.includes('created:')) {
      parsed.creationDate = line.split(':')[1]?.trim();
    } else if (lower.includes('expir')) {
      parsed.expirationDate = line.split(':')[1]?.trim();
    } else if (lower.includes('registrant country:')) {
      parsed.registrantCountry = line.split(':')[1]?.trim();
    }
  }
  
  // Extract emails
  parsed.emails = extractEmails(rawData);
  
  // Extract name servers
  const nsRegex = /name server:\s*([^\s]+)/gi;
  const nameServers = [];
  let match;
  while ((match = nsRegex.exec(rawData)) !== null) {
    nameServers.push(match[1]);
  }
  parsed.nameServers = nameServers;
  
  return parsed;
}

function extractEmails(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = text.match(emailRegex) || [];
  return [...new Set(emails)];
}

// Start server
app.listen(PORT, () => {
  console.log(`WHOIS Backend Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

module.exports = app;