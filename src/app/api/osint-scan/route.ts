
import { NextResponse } from 'next/server';
import whois from 'whois-json';
import sslChecker from 'ssl-checker';
import { URL } from 'url';

// --- OSINT Check Functions ---

async function getWhoisData(domain: string) {
    try {
        const data = await whois(domain);
        return {
            domain: data.domainName,
            registrar: data.registrar,
            creationDate: data.creationDate,
            expirationDate: data.expirationDate,
            nameservers: data.nameServer,
        };
    } catch (error) {
        console.error(`Whois lookup failed for ${domain}:`, error);
        return { domain, error: 'Failed to retrieve Whois data.' };
    }
}

async function getSslTlsData(domain: string) {
    try {
        const data = await sslChecker(domain);
        return {
            domain,
            valid: data.valid,
            validFrom: data.validFrom,
            validTo: data.validTo,
            daysRemaining: data.daysRemaining,
            issuer: data.issuer,
        };
    } catch (error: any) {
        console.error(`SSL/TLS check failed for ${domain}:`, error);
        return { domain, error: `SSL/TLS check failed: ${error.message}` };
    }
}

// NOTE: Placeholders for API-key-based services
async function getVirusTotalData(domain: string) {
    return { domain, message: 'VirusTotal analysis not yet implemented.' };
}

async function getShodanData(domain: string) {
    return { domain, message: 'Shodan lookup not yet implemented.' };
}


// --- API Endpoint ---

export async function POST(request: Request) {
    const { url } = await request.json();

    if (!url) {
        return NextResponse.json({ error: 'No URL provided' }, { status: 400 });
    }

    let domain;
    try {
        domain = new URL(url).hostname;
    } catch (error) {
        return NextResponse.json({ error: 'Invalid URL provided' }, { status: 400 });
    }

    try {
        const [whoisData, sslTlsData, virusTotalData, shodanData] = await Promise.all([
            getWhoisData(domain),
            getSslTlsData(domain),
            getVirusTotalData(domain),
            getShodanData(domain)
        ]);

        return NextResponse.json({
            whois: whoisData,
            ssl: sslTlsData,
            virustotal: virusTotalData,
            shodan: shodanData,
        });

    } catch (error: any) {
        console.error(`OSINT scan failed for domain ${domain}:`, error);
        return NextResponse.json({ error: `An unexpected error occurred during the OSINT scan.` }, { status: 500 });
    }
}
