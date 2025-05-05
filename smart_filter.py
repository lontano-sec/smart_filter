#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
from collections import defaultdict
from urllib.parse import urlparse, urlunparse, parse_qsl
import tqdm
import argparse

# --- Configuration for Low-Value Patterns ---
# You can customize these lists
LOW_VALUE_DOMAINS = ['www.browserstack.com']
LOW_VALUE_PATHS_CONTAIN = ['/screenshots/']
LOW_VALUE_EXTENSIONS = [
    '.jpg', '.jpeg', '.gif', '.png', '.ico', '.svg', '.webp', '.bmp',
    '.mp3', '.wav', '.mp4', '.webm', '.avi', '.mov', '.flv', '.ogg',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.css', '.map',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.gz', '.tar', '.bz2', '.7z'
]
TRACKING_KEYWORDS = ['ga.js', 'gtm.js', 'analytics', 'pixel.js', 'track', 'beacon']
COMMON_JS_LIBS = ['jquery', 'bootstrap', 'react', 'vue', 'angular', 'axios', 'lodash', 'moment', 'modernizr']

def normalize_url(url):
    """
    Normalize URL by:
    - Removing default ports (HTTP:80, HTTPS:443)
    - Removing trailing slashes from paths (unless it's just "/")
    - Sorting query parameters alphabetically
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Handle port
        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
            if port.isdigit():
                port_num = int(port)
                if (scheme == 'http' and port_num == 80) or \
                   (scheme == 'https' and port_num == 443):
                    netloc = host # Remove default ports

        # Handle path, remove trailing slash (if path is not just "/")
        path = parsed.path
        if not path:
             path = '/' # Ensure path exists
        elif path.endswith('/') and len(path) > 1:
            path = path[:-1]

        # Parse and rebuild query parameters (sorted alphabetically)
        query_params = parse_qsl(parsed.query, keep_blank_values=True) # keep blanks
        sorted_query = '&'.join(
            f"{k}={v}" for k, v in sorted(query_params)
        ) if query_params else ''

        # Rebuild URL
        normalized = urlunparse((
            scheme,
            netloc,
            path,
            parsed.params, # Usually empty
            sorted_query,
            parsed.fragment # Keep fragment
        ))
        return normalized
    except Exception as e:
        # print(f"Error normalizing URL: {url}, Error: {e}") # Optional: uncomment for debugging
        return url # Return original if error

def get_url_pattern(url):
    """
    Generate a more generic URL pattern for grouping similar URLs.
    Replaces numbers, UUIDs, long hashes, and specific file names in common paths.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path

        # If path is empty or just /, use domain name as pattern
        if not path or path == '/':
            return f"{domain}/"

        pattern_path = path

        # Replace potential UUIDs
        pattern_path = re.sub(r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '/{uuid}', pattern_path)
        # Replace long hex strings (e.g., hashes, IDs) - adjust length threshold if needed
        pattern_path = re.sub(r'/[0-9a-fA-F]{20,}', '/{long_hash}', pattern_path)
        # Replace common SHA1/MD5 like hashes
        pattern_path = re.sub(r'/[0-9a-fA-F]{32}', '/{hash32}', pattern_path)
        pattern_path = re.sub(r'/[0-9a-fA-F]{40}', '/{hash40}', pattern_path)

        # Replace screenshot filenames more generically (example)
        if '/screenshots/' in pattern_path.lower() and any(pattern_path.lower().endswith(ext) for ext in LOW_VALUE_EXTENSIONS):
             pattern_path = re.sub(r'/[^/]+\.(?:' + '|'.join(ext.lstrip('.') for ext in LOW_VALUE_EXTENSIONS) + r')$', '/{media_file}', pattern_path, flags=re.IGNORECASE)

        # Replace all numbers with {num} last, to avoid interfering with hashes etc.
        pattern_path = re.sub(r'\d+', '{num}', pattern_path)

        # Extract query parameter names (sorted, ignoring values)
        param_names = sorted(dict(parse_qsl(parsed.query)).keys())
        param_signature = ','.join(param_names) if param_names else ''

        # Use lowercase path for the final pattern key
        return f"{domain}{pattern_path.lower()}?{param_signature}"
    except Exception as e:
        # print(f"Error getting URL pattern: {url}, Error: {e}") # Optional: uncomment for debugging
        return url # Fallback to original URL or a generic error pattern

def score_url(url):
    """
    Evaluate URL's potential vulnerability value (0-100 score).
    Heavily penalizes known low-value patterns.
    Returns score and reasoning.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query
        scheme = parsed.scheme.lower()

        score = 50  # Default medium score
        reason = []

        # --- Start with Explicit Exclusions / Heavy Penalties ---
        if any(d == domain for d in LOW_VALUE_DOMAINS):
            if any(p in path for p in LOW_VALUE_PATHS_CONTAIN):
                 return 1, "Excluded domain/path pattern" # Give minimal score to ensure removal if min_score > 1

        if any(path.endswith(ext) for ext in LOW_VALUE_EXTENSIONS):
            score = 5 # Start with a very low score for static files
            reason.append("Low-value static file type")
        # --- End Explicit Exclusions ---


        # Boost HTTPS
        if scheme == 'https':
            score += 5
            reason.append("HTTPS")

        # Parameters boost score significantly
        if query:
            params = dict(parse_qsl(query))
            param_count = len(params)
            if param_count > 0:
                score_add = min(30, 5 + param_count * 5) # More aggressive boost for params
                score += score_add
                reason.append(f"{param_count} params")

                sensitive_params = ['id', 'user', 'pass', 'pwd', 'password', 'login', 'admin', 'uid',
                                  'key', 'token', 'auth', 'file', 'path', 'dir', 'load', 'action',
                                  'download', 'upload', 'name', 'type', 'email', 'redirect', 'url',
                                  'callback', 'return', 'next', 'target', 'goto', 'continue', # Added common redirect params
                                  'cmd', 'exec', 'command', 'query', 'sql', 'search', 'term', # Added common injection params
                                  'include', 'page', 'view', 'content'] # Added common LFI/RFI params

                found_sensitive = [p for p in params.keys() if any(s == p.lower() or s in p.lower() for s in sensitive_params)]
                if found_sensitive:
                    score += min(25, len(found_sensitive) * 6) # Slightly higher boost
                    reason.append(f"Sensitive params: {', '.join(found_sensitive)}")
            else: # query exists but no params parsed? (e.g., "?") - unlikely but penalize
                 score -= 10
                 reason.append("Query string present but no params")
        else:
            # Penalize URLs without parameters UNLESS they have high-value extensions/keywords
            if not any(path.endswith(ext) for ext in ['.php', '.asp', '.aspx', '.jsp', '.do', '.action']) and \
               not any(k in path for k in ['api', 'admin', 'login', 'upload', 'download']):
                score -= 15
                reason.append("No params & non-dynamic path/extension")

        # Penalize tracking scripts
        if any(t in path for t in TRACKING_KEYWORDS):
            score -= 40 # Increased penalty
            reason.append("Analytics/tracking script")

        # Penalize common JS libraries
        if path.endswith('.js') and any(lib in path for lib in COMMON_JS_LIBS):
            score -= 30 # Increased penalty
            reason.append("Common JS library")
        elif path.endswith('.js'):
            score += 5 # Boost custom JS
            reason.append("Custom JS file")

        # Check for valuable path keywords
        valuable_keywords = ['admin', 'manage', 'dashboard', 'console', 'login', 'api', 'graphql', 'user', # Added graphql
                           'account', 'profile', 'config', 'setup', 'setting', 'upload',
                           'download', 'file', 'report', 'edit', 'delete', 'create', 'add',
                           'test', 'dev', 'beta', 'internal', 'staff', 'sys', 'system',
                           'ajax', 'json', 'xml', 'rpc', 'service', 'backend', 'private', 'proxy'] # Added proxy

        found_valuable = [k for k in valuable_keywords if k in path]
        if found_valuable:
            score += min(25, len(found_valuable) * 5)
            reason.append(f"Valuable keywords: {', '.join(found_valuable)}")

        # Boost high-value file types (dynamic pages, potentially sensitive configs/backups)
        valuable_extensions = ['.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.cgi',
                             '.pl', '.py', '.rb', '.sh', '.cfm', # Added cfm
                             '.json', '.xml', '.sql', '.config', '.yml', '.yaml', # Added yml/yaml
                             '.ini', '.env', '.log', '.bak', '.old', '.backup', '.swp', '.sqlitedb'] # Added swp, sqlitedb

        if any(path.endswith(ext) for ext in valuable_extensions):
            # Don't double penalize/reward if already handled by static file check
            if not any(path.endswith(ext) for ext in LOW_VALUE_EXTENSIONS):
                score += 20 # Increased boost
                reason.append("High-value file type")

        # Check path complexity (simple measure)
        path_parts = [p for p in path.split('/') if p]
        if len(path_parts) > 4: # Slightly increased threshold
            score += 10
            reason.append("Complex path")

        # Check for API endpoints patterns
        if '/api/' in path or '/v1/' in path or '/v2/' in path or re.search(r'/v\d+/', path):
            score += 25 # Increased boost
            reason.append("API endpoint pattern")

        # Normalize score to 0-100 range
        score = max(0, min(100, score))

        return score, ", ".join(reason)

    except Exception as e:
        # print(f"Error scoring URL: {url}, Error: {e}") # Optional: uncomment for debugging
        return 0, f"Scoring error: {e}" # Return 0 score on error

def filter_urls(input_file, output_file=None, min_score=30, prefer_https=True, verbose=True):
    """
    Filter URL list based on the following rules:
    1. Normalize URLs and remove exact duplicates (post-normalization).
    2. Prioritize HTTPS versions if prefer_https is True.
    3. Score each URL for "vulnerability value".
    4. Filter out URLs scoring below min_score.
    5. Group remaining URLs by a generated pattern.
    6. Keep only the single highest-scoring URL for each unique pattern.
    """
    if verbose:
        print(f"Starting URL filtering process...")
        print(f" - Minimum score threshold: {min_score}")
        print(f" - Prioritize HTTPS: {prefer_https}")

    # Read all URLs
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip() and (line.startswith('http://') or line.startswith('https://'))]
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return []
    except Exception as e:
        print(f"Error reading input file '{input_file}': {e}")
        return []


    original_count = len(urls)
    if verbose:
        print(f"Read {original_count} potentially valid URLs")
    if original_count == 0:
        print("No URLs to process.")
        return []

    # --- Step 1: Normalize URLs and map back to original ---
    url_map = {} # normalized -> original
    normalized_set = set()
    normalized_list_for_proto_pref = [] # Keep order for protocol pref later

    for url in urls:
        norm_url = normalize_url(url)
        if norm_url not in normalized_set:
             normalized_set.add(norm_url)
             url_map[norm_url] = url # Store first original URL for this normalized version
             normalized_list_for_proto_pref.append(norm_url)

    dedup_count = len(normalized_list_for_proto_pref)
    if verbose:
        print(f"After normalization and deduplication: {dedup_count} unique URLs")


    # --- Step 2: Handle HTTP/HTTPS protocol preference ---
    if prefer_https:
        protocol_deduplicated_map = {} # key: url_without_protocol, value: chosen_url (https pref)
        for norm_url in normalized_list_for_proto_pref:
             # Create key by removing scheme
             no_protocol_key = re.sub(r'^https?://', '', norm_url)

             if no_protocol_key not in protocol_deduplicated_map:
                 # First time seeing this path/query, add it
                 protocol_deduplicated_map[no_protocol_key] = norm_url
             else:
                 # We've seen this path/query before, check protocol
                 existing_url = protocol_deduplicated_map[no_protocol_key]
                 if norm_url.startswith('https://') and not existing_url.startswith('https://'):
                     # Current is HTTPS, existing is HTTP -> Replace with HTTPS version
                     protocol_deduplicated_map[no_protocol_key] = norm_url
                 # else: keep the existing one (either it was already HTTPS or both are HTTP)

        urls_to_process = list(protocol_deduplicated_map.values())
        proto_pref_count = len(urls_to_process)
        if verbose:
            print(f"After HTTPS preference: {proto_pref_count} URLs")
    else:
        urls_to_process = normalized_list_for_proto_pref # Use the initially deduplicated list
        proto_pref_count = dedup_count


    # --- Step 3 & 4: Score URLs and filter by min_score ---
    if verbose:
        print(f"Scoring {proto_pref_count} URLs...")

    url_scores = {}
    # Use tqdm for progress bar only if verbose and processing many URLs
    url_iterator = tqdm.tqdm(urls_to_process, desc="Scoring URLs") if verbose and proto_pref_count > 1000 else urls_to_process

    for url in url_iterator:
        score, reason = score_url(url)
        if score >= min_score:
            url_scores[url] = (score, reason)

    scored_count = len(url_scores)
    if verbose:
        print(f"Found {scored_count} URLs meeting min_score >= {min_score}")
    if scored_count == 0:
         print("No URLs met the minimum score criteria.")
         if output_file: # Create empty output file
              open(output_file, 'w').close()
         return []


    # --- Step 5 & 6: Group by pattern and keep ONE best per pattern ---
    if verbose:
        print("Grouping by pattern and selecting best URL per pattern...")

    pattern_groups = defaultdict(list)
    for url in url_scores.keys():
        pattern = get_url_pattern(url)
        pattern_groups[pattern].append(url)

    final_normalized_urls = []
    pattern_iterator = tqdm.tqdm(pattern_groups.items(), desc="Filtering Patterns") if verbose and len(pattern_groups) > 500 else pattern_groups.items()

    for pattern, pattern_urls in pattern_iterator:
        if not pattern_urls: continue

        # Find the URL with the highest score in this pattern group
        # max() picks arbitrarily if scores are equal
        best_url_in_pattern = max(pattern_urls, key=lambda u: url_scores[u][0])
        final_normalized_urls.append(best_url_in_pattern)

    # --- Final Steps ---
    # Sort final list by score for potential review/output ordering
    final_normalized_urls.sort(key=lambda u: url_scores[u][0], reverse=True)

    # Restore original URLs using the map
    final_original_urls = [url_map.get(norm_url, norm_url) for norm_url in final_normalized_urls] # Fallback to norm_url if somehow missing

    final_count = len(final_original_urls)

    # Write filtered URLs to output file
    if output_file:
        if verbose:
             print(f"Writing {final_count} URLs to '{output_file}'...")
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in final_original_urls:
                    f.write(f"{url}\n")
        except Exception as e:
             print(f"Error writing to output file '{output_file}': {e}")


    # Print summary stats
    if verbose:
        print(f"\n--- Filtering Summary ---")
        print(f"Initial URLs read:         {original_count}")
        if original_count > 0:
             print(f"Unique Normalized URLs:    {dedup_count} ({round(dedup_count/original_count*100,1)}%)")
             if prefer_https:
                 print(f"After HTTPS Preference:    {proto_pref_count} ({round(proto_pref_count/original_count*100,1)}%)")
             print(f"URLs >= Min Score ({min_score}):   {scored_count} ({round(scored_count/original_count*100,1)}%)")
             print(f"Final URLs (Best per pattern): {final_count} ({round(final_count/original_count*100,1)}%)")

             if scored_count > 0:
                  print(f"\nTop 10 Kept URLs by Score:")
                  for i, url in enumerate(final_normalized_urls[:10], 1):
                      score, reason = url_scores.get(url, (-1, "Score not found")) # Safely get score
                      original_url = url_map.get(url, url)
                      print(f"  {i}. [Score: {score}] {original_url}")
                      # print(f"      Reason: {reason}") # Uncomment for more detail
                      # print(f"      Pattern: {get_url_pattern(url)}") # Uncomment for pattern debug
        else:
             print("No valid URLs were processed.")


    return final_original_urls

def main():
    parser = argparse.ArgumentParser(
        description='Filter and prioritize URLs for vulnerability hunting by removing low-value and redundant entries.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help
    )
    parser.add_argument('input_file', help='Input file containing URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output file for filtered URLs', default='filtered_urls.txt')
    parser.add_argument('-m', '--min-score', type=int, help='Minimum URL score (0-100) required to be considered', default=30) # Default slightly higher
    parser.add_argument('--no-https-preference', action='store_false', dest='prefer_https',
                        help='Do not prioritize HTTPS URLs over HTTP equivalents')
    parser.add_argument('-q', '--quiet', action='store_false', dest='verbose',
                        help='Quiet mode (minimal output)')

    args = parser.parse_args()

    # Run filtering
    filtered_list = filter_urls(
        args.input_file,
        args.output,
        args.min_score,
        args.prefer_https,
        args.verbose
    )

    if args.verbose:
         if filtered_list:
              print(f"\nProcess finished. Found {len(filtered_list)} valuable URLs.")
         else:
              print("\nProcess finished. No valuable URLs found matching the criteria.")

if __name__ == "__main__":
    main()
