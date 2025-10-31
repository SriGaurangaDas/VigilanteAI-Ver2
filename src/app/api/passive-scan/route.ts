
import { NextResponse } from 'next/server';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { URL } from 'url';

const VULNERABILITY_DB = {
    // Security Headers
    MISSING_CSP: { title: 'Missing Content-Security-Policy (CSP)', severity: 'Medium', description: 'The page is missing a CSP, which helps to detect and mitigate attacks like XSS and data injection.', recommendation: 'Implement a strong CSP via an HTTP response header.' },
    MISSING_HSTS: { title: 'Missing Strict-Transport-Security (HSTS)', severity: 'Medium', description: 'The site does not use HSTS, which prevents browsers from connecting over insecure HTTP.', recommendation: 'Implement the `Strict-Transport-Security` header on all HTTPS responses.' },
    MISSING_X_FRAME_OPTIONS: { title: 'Missing X-Frame-Options', severity: 'Medium', description: 'The page is missing the `X-Frame-Options` header, leaving it vulnerable to clickjacking attacks.', recommendation: 'Set the `X-Frame-Options` header to `DENY` or `SAMEORIGIN`.' },
    MISSING_X_CONTENT_TYPE_OPTIONS: { title: 'Missing X-Content-Type-Options', severity: 'Low', description: 'The `X-Content-Type-Options` header is not set to `nosniff`, which can lead to MIME-sniffing attacks.', recommendation: 'Set the `X-Content-Type-Options` header to `nosniff`.' },
    SERVER_FINGERPRINTING: { title: 'Server Version Information Leaked', severity: 'Low', description: 'The `Server` header reveals specific version information, which can help attackers find known vulnerabilities.', recommendation: 'Suppress or unset the `Server` header, or set it to a generic value.' },

    // Insecure Content
    MIXED_CONTENT: { title: 'Mixed Content', severity: 'Medium', description: 'The HTTPS page loads insecure content (e.g., images, scripts) over HTTP.', recommendation: 'Ensure all content is loaded over HTTPS.' },
    INSECURE_FORM: { title: 'Insecure Form', severity: 'High', description: 'A form on the page submits data over an insecure HTTP connection.', recommendation: 'Ensure all forms submit data over HTTPS.' },
    AUTOCOMPLETE_ON_PASSWORD: { title: 'Password Field with Autocomplete', severity: 'Low', description: 'A password input field has autocomplete enabled, which can be a security risk in shared environments.', recommendation: 'Add `autocomplete="new-password"` to all password fields.' },
    MISSING_REL_NOOPENER: { title: 'Missing rel="noopener noreferrer"', severity: 'Low', description: 'Links using `target="_blank"` are missing `rel="noopener noreferrer"`, which can lead to tabnabbing vulnerabilities.', recommendation: 'Add `rel="noopener noreferrer"` to all links that open in a new tab.' },

    // Information Disclosure
    VERBOSE_COMMENTS: { title: 'Verbose HTML Comments', severity: 'Low', description: 'The page contains HTML comments with potentially sensitive information (e.g., "TODO", "FIXME", "DEBUG").', recommendation: 'Review and remove any sensitive information from HTML comments before deployment.' },

    // Cookie Security
    COOKIE_MISSING_HTTPONLY: { title: 'Cookie Missing HttpOnly Flag', severity: 'Medium', description: 'A cookie is missing the `HttpOnly` flag, making it accessible to client-side scripts and vulnerable to XSS.', recommendation: 'Set the `HttpOnly` flag for all cookies that do not need to be accessed by JavaScript.' },
    COOKIE_MISSING_SECURE: { title: 'Cookie Missing Secure Flag', severity: 'Medium', description: 'A cookie is missing the `Secure` flag, meaning it can be transmitted over unencrypted HTTP connections.', recommendation: 'Set the `Secure` flag for all cookies on HTTPS sites.' },
    COOKIE_MISSING_SAMESITE: { title: 'Cookie Missing SameSite Attribute', severity: 'Medium', description: 'A cookie is missing the `SameSite` attribute, which can make the site vulnerable to Cross-Site Request Forgery (CSRF) attacks.', recommendation: 'Set the `SameSite` attribute to `Lax` or `Strict` for all cookies.' },
};

function run_checks(soup: cheerio.CheerioAPI, headers: any, url: string, html_content: string) {
    const findings: any[] = [];

    findings.push(...check_security_headers(headers, url));
    findings.push(...check_insecure_content(soup, url));
    findings.push(...check_information_disclosure(html_content));
    findings.push(...check_cookie_security(headers, url));

    return findings;
}

function check_security_headers(headers: any, url: string) {
    const findings = [];
    const parsedUrl = new URL(url);

    if (!headers['content-security-policy']) findings.push({ id: 'MISSING_CSP', details: 'No CSP header found.' });
    if (parsedUrl.protocol === 'https:' && !headers['strict-transport-security']) findings.push({ id: 'MISSING_HSTS', details: 'No HSTS header found on this HTTPS site.' });
    if (!headers['x-frame-options']) findings.push({ id: 'MISSING_X_FRAME_OPTIONS', details: 'No X-Frame-Options header found.' });
    if (!headers['x-content-type-options'] || !headers['x-content-type-options'].includes('nosniff')) findings.push({ id: 'MISSING_X_CONTENT_TYPE_OPTIONS', details: 'X-Content-Type-Options header is missing or not set to "nosniff".' });
    if (headers['server']) findings.push({ id: 'SERVER_FINGERPRINTING', details: `The "Server" header is set to: "${headers['server']}"` });

    return findings;
}

function check_insecure_content(soup: cheerio.CheerioAPI, url: string) {
    const findings = [];
    const parsedUrl = new URL(url);

    if (parsedUrl.protocol === 'https:') {
        soup('img, script, link[rel="stylesheet"]').each((i, elem) => {
            const src = soup(elem).attr('src') || soup(elem).attr('href');
            if (src && src.startsWith('http://')) {
                findings.push({ id: 'MIXED_CONTENT', details: `Insecure content loaded from: ${src}` });
            }
        });
    }

    soup('form').each((i, elem) => {
        const action = soup(elem).attr('action');
        if (action && action.startsWith('http://')) {
            findings.push({ id: 'INSECURE_FORM', details: `Form submits to an insecure HTTP URL: ${action}` });
        }
    });

    soup('input[type="password"]').each((i, elem) => {
        const autocomplete = soup(elem).attr('autocomplete');
        if (autocomplete !== 'off' && autocomplete !== 'new-password') {
            findings.push({ id: 'AUTOCOMPLETE_ON_PASSWORD', details: 'Password field has autocomplete enabled.' });
        }
    });

    soup('a[target="_blank"]').each((i, elem) => {
        const rel = soup(elem).attr('rel');
        if (!rel || (!rel.includes('noopener') || !rel.includes('noreferrer'))) {
            findings.push({ id: 'MISSING_REL_NOOPENER', details: `Link with target="_blank" is missing rel="noopener noreferrer": ${soup(elem).attr('href')}` });
        }
    });

    return findings;
}

function check_information_disclosure(html_content: string) {
    const findings = [];

    const commentRegex = /<!--[\s\S]*?-->/g;
    const sensitiveKeywords = ['todo', 'fixme', 'debug', 'password', 'secret'];
    const comments = html_content.match(commentRegex) || [];

    comments.forEach(comment => {
        const lowerCaseComment = comment.toLowerCase();
        sensitiveKeywords.forEach(keyword => {
            if (lowerCaseComment.includes(keyword)) {
                findings.push({ id: 'VERBOSE_COMMENTS', details: `Found a comment containing the keyword "${keyword}": ${comment.substring(0, 100)}...` });
            }
        });
    });

    return findings;
}

function check_cookie_security(headers: any, url: string) {
    const findings = [];
    const setCookieHeader = headers['set-cookie'];
    if (!setCookieHeader) return findings;

    const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    const parsedUrl = new URL(url);

    cookies.forEach(cookieStr => {
        const cookieName = cookieStr.split('=')[0];
        const lowerCaseCookie = cookieStr.toLowerCase();

        if (!lowerCaseCookie.includes('httponly')) {
            findings.push({ id: 'COOKIE_MISSING_HTTPONLY', details: `Cookie "${cookieName}" is missing the HttpOnly flag.` });
        }
        if (parsedUrl.protocol === 'https:' && !lowerCaseCookie.includes('secure')) {
            findings.push({ id: 'COOKIE_MISSING_SECURE', details: `Cookie "${cookieName}" is missing the Secure flag on an HTTPS site.` });
        }
        if (!lowerCaseCookie.includes('samesite')) {
            findings.push({ id: 'COOKIE_MISSING_SAMESITE', details: `Cookie "${cookieName}" is missing the SameSite attribute.` });
        }
    });

    return findings;
}


export async function POST(request: Request) {
  const { url } = await request.json();

  if (!url) return NextResponse.json({ error: 'No URL provided' }, { status: 400 });
  if (!url.startsWith('http://') && !url.startsWith('https://')) return NextResponse.json({ error: 'Invalid URL. Must start with http:// or https://' }, { status: 400 });

  try {
    const response = await axios.get(url, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      timeout: 10000
    });

    const html_content = response.data;
    const headers = response.headers;
    const soup = cheerio.load(html_content);

    const findings = run_checks(soup, headers, url, html_content);

    const populated_findings = findings.map(finding => ({
        ...VULNERABILITY_DB[finding.id as keyof typeof VULNERABILITY_DB],
        ...finding
    }));

    return NextResponse.json(populated_findings);
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
        return NextResponse.json({ error: `Failed to fetch URL: ${error.message}` }, { status: 500 });
    }
    return NextResponse.json({ error: `An unexpected error occurred: ${error.message}` }, { status: 500 });
  }
}
