#!/usr/bin/env python3
"""
Chaos Data Collector Pro - Advanced Target Aggregation System
Version: 2.0.0 | Author: Security Operations Team
"""

import os
import sys
import json
import time
import logging
import argparse
import hashlib
import zipfile
import tempfile
import subprocess
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse
import re
import shutil
import tarfile
import gzip
import socket
import signal

# Third-party imports (install with pip install -r requirements.txt)
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    import tqdm
    from colorama import init, Fore, Style
    from dataclasses import dataclass, asdict
    from enum import Enum
    import dns.resolver
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Install with: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"

@dataclass
class CollectionStats:
    total_urls: int = 0
    downloaded: int = 0
    failed: int = 0
    extracted: int = 0
    total_domains: int = 0
    duplicates_removed: int = 0
    start_time: float = 0
    end_time: float = 0

class DomainValidator:
    """Domain validation and processing utilities"""
    
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    IP_REGEX = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        """Validate domain format"""
        domain = domain.strip().lower()
        
        # Skip empty lines
        if not domain:
            return False
        
        # Skip IP addresses
        if cls.IP_REGEX.match(domain):
            return False
        
        # Check domain format
        if not cls.DOMAIN_REGEX.match(domain):
            return False
        
        # Check for common false positives
        invalid_patterns = [
            'example.com', 'example.org', 'test.com',
            'localhost', 'localdomain', 'invalid',
        ]
        
        if any(pattern in domain for pattern in invalid_patterns):
            return False
        
        return True
    
    @classmethod
    def extract_tld(cls, domain: str) -> str:
        """Extract TLD from domain"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-1]
        return ''
    
    @classmethod
    def extract_domain(cls, domain: str) -> str:
        """Extract base domain (e.g., example.com from sub.example.com)"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return domain

class DNSResolver:
    """DNS resolution utilities"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def resolve(self, domain: str) -> bool:
        """Check if domain resolves to any IP"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return len(answers) > 0
        except:
            try:
                answers = self.resolver.resolve(domain, 'AAAA')
                return len(answers) > 0
            except:
                return False
    
    def bulk_resolve(self, domains: List[str], max_workers: int = 10) -> Dict[str, bool]:
        """Resolve multiple domains in parallel"""
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {
                executor.submit(self.resolve, domain): domain 
                for domain in domains[:1000]  # Limit for performance
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    results[domain] = future.result()
                except Exception:
                    results[domain] = False
        
        return results

class ChaosCollector:
    """Main Chaos Data Collector class"""
    
    def __init__(self, args):
        self.args = args
        self.config = self._load_config()
        self.stats = CollectionStats()
        self.session = self._create_session()
        
        # Setup directories
        self.output_dir = Path(args.output_dir).resolve()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="chaos_"))
        self.log_file = self.output_dir / f"chaos_collector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        # Setup logging
        self._setup_logging()
        
        # Initialize components
        self.validator = DomainValidator()
        self.resolver = DNSResolver() if args.resolve_dns else None
        
        # State tracking
        self.downloaded_urls = set()
        self.resume_file = self.output_dir / "downloaded_urls.txt"
        
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        config_path = Path.home() / ".chaos_collector.json"
        default_config = {
            "index_url": "https://chaos-data.projectdiscovery.io/index.json",
            "user_agent": "Chaos-Collector-Pro/2.0 (+https://github.com/security-tools)",
            "timeout": 30,
            "max_retries": 3,
            "parallel_downloads": 5,
            "validate_domains": True,
            "remove_duplicates": True,
            "enable_compression": True,
        }
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return {**default_config, **json.load(f)}
            except:
                return default_config
        return default_config
    
    def _save_config(self):
        """Save configuration to file"""
        config_path = Path.home() / ".chaos_collector.json"
        with open(config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.config['max_retries'],
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=100,
            pool_maxsize=100
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate',
        })
        
        return session
    
    def _setup_logging(self):
        """Setup logging configuration"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.DEBUG if self.args.verbose else logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler() if not self.args.quiet else logging.NullHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def log(self, level: LogLevel, message: str):
        """Log message with color"""
        colors = {
            LogLevel.DEBUG: Fore.BLUE,
            LogLevel.INFO: Fore.GREEN,
            LogLevel.WARN: Fore.YELLOW,
            LogLevel.ERROR: Fore.RED,
        }
        
        color = colors.get(level, '')
        
        if not self.args.quiet:
            print(f"{color}[{datetime.now().strftime('%H:%M:%S')}] [{level.value}] {message}{Style.RESET_ALL}")
        
        getattr(self.logger, level.value.lower())(message)
    
    def _print_banner(self):
        """Print tool banner"""
        banner = f"""{Fore.CYAN}
     ██████╗██╗  ██╗ █████╗  ██████╗ ███████╗    ██████╗ ██████╗ ██╗     
    ██╔════╝██║  ██║██╔══██╗██╔════╝ ██╔════╝    ██╔══██╗██╔══██╗██║     
    ██║     ███████║███████║██║  ███╗███████╗    ██║  ██║██████╔╝██║     
    ██║     ██╔══██║██╔══██║██║   ██║╚════██║    ██║  ██║██╔═══╝ ██║     
    ╚██████╗██║  ██║██║  ██║╚██████╔╝███████║    ██████╔╝██║     ███████╗
     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═════╝ ╚═╝     ╚══════╝
                                                                         
    ██████╗  ██████╗ ██╗   ██╗███████╗███████╗████████╗███████╗██████╗ 
    ██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
    ██║  ██║██║   ██║██║   ██║█████╗  ███████╗   ██║   █████╗  ██████╔╝
    ██║  ██║██║   ██║╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝ ╚████╔╝ ███████╗███████║   ██║   ███████╗██║  ██║
    ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    
    {Fore.YELLOW}Chaos Data Collector Pro v2.0 - Advanced Target Aggregation System{Style.RESET_ALL}
    {Fore.CYAN}For authorized security research and reconnaissance purposes only{Style.RESET_ALL}
    """
        print(banner)
    
    def download_index(self) -> Dict:
        """Download and parse the index.json file"""
        self.log(LogLevel.INFO, f"Downloading index from: {self.config['index_url']}")
        
        if self.args.dry_run:
            self.log(LogLevel.INFO, "[DRY RUN] Would download index")
            return {}
        
        try:
            response = self.session.get(
                self.config['index_url'],
                timeout=self.config['timeout']
            )
            response.raise_for_status()
            
            index_data = response.json()
            self.log(LogLevel.INFO, f"Index downloaded successfully")
            return index_data
            
        except Exception as e:
            self.log(LogLevel.ERROR, f"Failed to download index: {e}")
            raise
    
    def extract_urls(self, index_data: Dict) -> List[str]:
        """Extract dataset URLs from index"""
        urls = []
        
        for item in index_data:
            if 'URL' in item and item['URL']:
                urls.append(item['URL'])
        
        self.stats.total_urls = len(urls)
        self.log(LogLevel.INFO, f"Found {len(urls)} dataset URLs")
        
        # Filter already downloaded URLs if resuming
        if self.args.resume and self.resume_file.exists():
            with open(self.resume_file, 'r') as f:
                downloaded = set(line.strip() for line in f)
            
            urls = [url for url in urls if url not in downloaded]
            self.log(LogLevel.INFO, f"Resuming: {len(urls)} URLs remaining")
        
        return urls
    
    def download_file(self, url: str, output_path: Path) -> bool:
        """Download a single file with progress bar"""
        try:
            response = self.session.get(url, stream=True, timeout=self.config['timeout'])
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            
            with open(output_path, 'wb') as f, tqdm.tqdm(
                desc=output_path.name,
                total=total_size,
                unit='iB',
                unit_scale=True,
                leave=False,
                disable=self.args.quiet
            ) as pbar:
                for chunk in response.iter_content(chunk_size=8192):
                    size = f.write(chunk)
                    pbar.update(size)
            
            # Record downloaded URL
            with open(self.resume_file, 'a') as f:
                f.write(f"{url}\n")
            
            return True
            
        except Exception as e:
            self.log(LogLevel.WARN, f"Failed to download {url}: {e}")
            return False
    
    def download_datasets(self, urls: List[str]):
        """Download all datasets in parallel"""
        self.log(LogLevel.INFO, f"Downloading {len(urls)} datasets...")
        
        if self.args.dry_run:
            self.log(LogLevel.INFO, f"[DRY RUN] Would download {len(urls)} files")
            return
        
        download_dir = self.temp_dir / "downloads"
        download_dir.mkdir(exist_ok=True)
        
        # Create list of download tasks
        tasks = []
        for url in urls:
            filename = Path(urlparse(url).path).name
            output_path = download_dir / filename
            tasks.append((url, output_path))
        
        # Download in parallel
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config['parallel_downloads']
        ) as executor:
            futures = []
            for url, output_path in tasks:
                future = executor.submit(self.download_file, url, output_path)
                futures.append((future, url))
            
            # Process results
            for future, url in futures:
                success = future.result()
                if success:
                    self.stats.downloaded += 1
                else:
                    self.stats.failed += 1
        
        self.log(LogLevel.INFO, 
                f"Downloads completed: {self.stats.downloaded} success, {self.stats.failed} failed")
    
    def extract_archives(self):
        """Extract all ZIP archives"""
        self.log(LogLevel.INFO, "Extracting archives...")
        
        download_dir = self.temp_dir / "downloads"
        extract_dir = self.temp_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        
        for zip_path in download_dir.glob("*.zip"):
            try:
                archive_name = zip_path.stem
                target_dir = extract_dir / archive_name
                target_dir.mkdir(exist_ok=True)
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(target_dir)
                
                self.stats.extracted += 1
                self.log(LogLevel.DEBUG, f"Extracted: {archive_name}")
                
            except Exception as e:
                self.log(LogLevel.WARN, f"Failed to extract {zip_path.name}: {e}")
        
        self.log(LogLevel.INFO, f"Extracted {self.stats.extracted} archives")
    
    def process_domains(self) -> Set[str]:
        """Process and validate all collected domains"""
        self.log(LogLevel.INFO, "Processing domains...")
        
        extract_dir = self.temp_dir / "extracted"
        all_domains = set()
        
        # Collect all domains from text files
        for txt_file in extract_dir.rglob("*.txt"):
            try:
                with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        domain = line.strip()
                        if self.args.validate_domains:
                            if self.validator.is_valid_domain(domain):
                                all_domains.add(domain)
                        else:
                            all_domains.add(domain)
            except Exception as e:
                self.log(LogLevel.WARN, f"Error reading {txt_file}: {e}")
        
        # Remove duplicates and sort
        before_count = len(all_domains)
        unique_domains = sorted(all_domains)
        after_count = len(unique_domains)
        
        self.stats.duplicates_removed = before_count - after_count
        self.stats.total_domains = after_count
        
        self.log(LogLevel.INFO, 
                f"Processed {after_count} unique domains (removed {self.stats.duplicates_removed} duplicates)")
        
        return set(unique_domains)
    
    def generate_reports(self, domains: Set[str]):
        """Generate various output reports"""
        self.log(LogLevel.INFO, "Generating reports...")
        
        # Main domains file
        main_file = self.output_dir / self.args.output_file
        with open(main_file, 'w') as f:
            for domain in sorted(domains):
                f.write(f"{domain}\n")
        
        # TLD distribution
        tld_count = {}
        for domain in domains:
            tld = self.validator.extract_tld(domain)
            tld_count[tld] = tld_count.get(tld, 0) + 1
        
        with open(self.output_dir / "tld_distribution.txt", 'w') as f:
            for tld, count in sorted(tld_count.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{count:8} {tld}\n")
        
        # Domain distribution
        domain_count = {}
        for domain in domains:
            base_domain = self.validator.extract_domain(domain)
            domain_count[base_domain] = domain_count.get(base_domain, 0) + 1
        
        with open(self.output_dir / "domain_distribution.txt", 'w') as f:
            for base_domain, count in sorted(domain_count.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{count:8} {base_domain}\n")
        
        # Wildcard patterns for scanning
        with open(self.output_dir / "wildcard_patterns.txt", 'w') as f:
            wildcards = set()
            for domain in domains:
                base_domain = self.validator.extract_domain(domain)
                wildcards.add(f"*.{base_domain}")
            
            for pattern in sorted(wildcards):
                f.write(f"{pattern}\n")
        
        # Generate summary
        self._generate_summary(main_file)
    
    def _generate_summary(self, main_file: Path):
        """Generate summary statistics"""
        summary_file = self.output_dir / "collection_summary.json"
        
        summary = {
            "collection_date": datetime.now().isoformat(),
            "total_domains": self.stats.total_domains,
            "unique_domains": self.stats.total_domains,
            "duplicates_removed": self.stats.duplicates_removed,
            "datasets_downloaded": self.stats.downloaded,
            "datasets_failed": self.stats.failed,
            "archives_extracted": self.stats.extracted,
            "output_file": str(main_file),
            "file_size": main_file.stat().st_size if main_file.exists() else 0,
            "duration_seconds": time.time() - self.stats.start_time,
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
    
    def compress_output(self):
        """Compress output files"""
        if not self.args.enable_compression:
            return
        
        self.log(LogLevel.INFO, "Compressing output...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = self.output_dir / f"chaos_data_{timestamp}.tar.gz"
        
        with tarfile.open(archive_name, 'w:gz') as tar:
            for file in self.output_dir.glob("*"):
                if file.is_file() and not file.name.startswith('chaos_data_'):
                    tar.add(file, arcname=file.name)
        
        self.log(LogLevel.INFO, f"Archive created: {archive_name}")
    
    def cleanup(self):
        """Cleanup temporary files"""
        if self.args.cleanup:
            self.log(LogLevel.INFO, "Cleaning up temporary files...")
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        else:
            self.log(LogLevel.INFO, f"Temporary files kept in: {self.temp_dir}")
    
    def print_statistics(self):
        """Print collection statistics"""
        duration = time.time() - self.stats.start_time
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}COLLECTION STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"Total URLs in index:      {self.stats.total_urls:>10}")
        print(f"Successfully downloaded:   {self.stats.downloaded:>10}")
        print(f"Failed downloads:          {self.stats.failed:>10}")
        print(f"Archives extracted:        {self.stats.extracted:>10}")
        print(f"Total domains collected:   {self.stats.total_domains:>10}")
        print(f"Duplicates removed:        {self.stats.duplicates_removed:>10}")
        print(f"Collection duration:       {duration:>10.2f}s")
        print(f"Output directory:          {self.output_dir}")
        print(f"Output file:               {self.args.output_file}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Show file sizes
        if (self.output_dir / self.args.output_file).exists():
            size = (self.output_dir / self.args.output_file).stat().st_size
            print(f"Output file size:          {size/1024/1024:>9.2f} MB")
        
        # Show generated files
        print(f"\n{Fore.GREEN}Generated files:{Style.RESET_ALL}")
        for file in sorted(self.output_dir.glob("*")):
            if file.is_file():
                print(f"  • {file.name}")
    
    def run(self):
        """Main execution method"""
        self._print_banner()
        self.stats.start_time = time.time()
        
        try:
            # Load resume state if needed
            if self.args.resume:
                self.log(LogLevel.INFO, "Resume mode enabled")
            
            # Main collection pipeline
            index_data = self.download_index()
            urls = self.extract_urls(index_data)
            
            if not urls:
                self.log(LogLevel.WARN, "No URLs to process")
                return
            
            self.download_datasets(urls)
            self.extract_archives()
            domains = self.process_domains()
            
            if domains:
                self.generate_reports(domains)
                self.compress_output()
            
            self.cleanup()
            self.print_statistics()
            
            self.log(LogLevel.INFO, "Collection completed successfully")
            
        except KeyboardInterrupt:
            self.log(LogLevel.WARN, "Collection interrupted by user")
            self.cleanup()
            sys.exit(1)
        except Exception as e:
            self.log(LogLevel.ERROR, f"Collection failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Chaos Data Collector Pro - Advanced Target Aggregation System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -o data -p 10
  %(prog)s --resume --parallel 8 --no-cleanup
  %(prog)s -v --dry-run --validate
  %(prog)s --output-file custom_domains.txt --no-compression
        """
    )
    
    parser.add_argument("-o", "--output-dir", default="chaos_data",
                       help="Output directory (default: chaos_data)")
    parser.add_argument("-f", "--output-file", default="aggregated_domains.txt",
                       help="Output filename (default: aggregated_domains.txt)")
    parser.add_argument("-u", "--url", 
                       default="https://chaos-data.projectdiscovery.io/index.json",
                       help="Custom index.json URL")
    parser.add_argument("-p", "--parallel", type=int, default=5,
                       help="Parallel downloads (default: 5)")
    parser.add_argument("-r", "--retries", type=int, default=3,
                       help="Max retries per download (default: 3)")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                       help="Timeout in seconds (default: 30)")
    parser.add_argument("--resume", action="store_true",
                       help="Resume interrupted download")
    parser.add_argument("--validate", action="store_true", default=True,
                       help="Validate domain format (default: True)")
    parser.add_argument("--no-validate", dest="validate", action="store_false",
                       help="Disable domain validation")
    parser.add_argument("--deduplicate", action="store_true", default=True,
                       help="Remove duplicate domains (default: True)")
    parser.add_argument("--no-deduplicate", dest="deduplicate", action="store_false",
                       help="Disable deduplication")
    parser.add_argument("--compress", action="store_true", default=True,
                       help="Compress output files (default: True)")
    parser.add_argument("--no-compress", dest="compress", action="store_false",
                       help="Disable compression")
    parser.add_argument("--cleanup", action="store_true", default=True,
                       help="Cleanup temporary files (default: True)")
    parser.add_argument("--no-cleanup", dest="cleanup", action="store_false",
                       help="Keep temporary files")
    parser.add_argument("--resolve-dns", action="store_true",
                       help="Resolve domains to validate accessibility")
    parser.add_argument("--dry-run", action="store_true",
                       help="Simulate without downloading")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Suppress non-error output")
    parser.add_argument("--version", action="version", version="Chaos Data Collector Pro v2.0")
    
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Update config with command line arguments
    if args.url:
        config = ChaosCollector._load_config.__func__(ChaosCollector)
        config['index_url'] = args.url
        config['parallel_downloads'] = args.parallel
        config['max_retries'] = args.retries
        config['timeout'] = args.timeout
    
    collector = ChaosCollector(args)
    collector.run()

if __name__ == "__main__":
    main()