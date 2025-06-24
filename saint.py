#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
SAINT Security Suite - مجموعة أدوات أمنية متكاملة
تم تطويره بواسطة: Saudi Linux
'''

import argparse
import os
import sys
import time
import json
import socket
import ssl
import subprocess
import platform
import re
import ipaddress
import concurrent.futures
import requests
import hashlib
from datetime import datetime
from colorama import init, Fore, Style, Back

# تهيئة الألوان
init(autoreset=True)

class SAINTSecuritySuite:
    def __init__(self):
        self.version = "1.0.0"
        self.author = "Saudi Linux"
        self.show_banner()
        self.args = self.parse_arguments()
        self.target = self.args.target
        self.output_dir = self.args.output
        self.threads = self.args.threads
        self.timeout = self.args.timeout
        self.verbose = self.args.verbose
        self.results = {}
        self.start_time = time.time()
        
        # إنشاء مجلد للنتائج إذا لم يكن موجودًا
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def show_banner(self):
        banner = f'''
{Fore.RED}  ███████╗ █████╗ ██╗███╗   ██╗████████╗{Style.RESET_ALL}
{Fore.RED}  ██╔════╝██╔══██╗██║████╗  ██║╚══██╔══╝{Style.RESET_ALL}
{Fore.RED}  ███████╗███████║██║██╔██╗ ██║   ██║   {Style.RESET_ALL}
{Fore.RED}  ╚════██║██╔══██║██║██║╚██╗██║   ██║   {Style.RESET_ALL}
{Fore.RED}  ███████║██║  ██║██║██║ ╚████║   ██║   {Style.RESET_ALL}
{Fore.RED}  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   {Style.RESET_ALL}
{Fore.BLUE}  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗{Style.RESET_ALL}
{Fore.BLUE}  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝{Style.RESET_ALL}
{Fore.BLUE}  ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ {Style.RESET_ALL}
{Fore.BLUE}  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  {Style.RESET_ALL}
{Fore.BLUE}  ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   {Style.RESET_ALL}
{Fore.BLUE}  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   {Style.RESET_ALL}
{Fore.GREEN}  ███████╗██╗   ██╗██╗████████╗███████╗{Style.RESET_ALL}
{Fore.GREEN}  ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝{Style.RESET_ALL}
{Fore.GREEN}  ███████╗██║   ██║██║   ██║   █████╗  {Style.RESET_ALL}
{Fore.GREEN}  ╚════██║██║   ██║██║   ██║   ██╔══╝  {Style.RESET_ALL}
{Fore.GREEN}  ███████║╚██████╔╝██║   ██║   ███████╗{Style.RESET_ALL}
{Fore.GREEN}  ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝{Style.RESET_ALL}
                                                  
        {Fore.CYAN}[ تم تطويره بواسطة: {self.author} ]{Style.RESET_ALL}
        {Fore.CYAN}[ الإصدار: {self.version} ]{Style.RESET_ALL}
        '''
        print(banner)
    
    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='SAINT Security Suite - مجموعة أدوات أمنية متكاملة')
        parser.add_argument('-t', '--target', help='الهدف المراد فحصه (مثال: example.com أو 192.168.1.1)')
        parser.add_argument('-o', '--output', help='مجلد حفظ النتائج')
        parser.add_argument('--threads', type=int, default=10, help='عدد العمليات المتزامنة (الافتراضي: 10)')
        parser.add_argument('--timeout', type=int, default=30, help='مهلة الاتصال بالثواني (الافتراضي: 30)')
        parser.add_argument('-v', '--verbose', action='store_true', help='عرض معلومات تفصيلية')
        
        # إضافة مجموعات الأوامر الفرعية
        subparsers = parser.add_subparsers(dest='module', help='وحدات الفحص المتاحة')
        
        # وحدة فحص الشبكة
        network_parser = subparsers.add_parser('network', help='وحدة فحص الشبكة')
        network_parser.add_argument('--scan', choices=['basic', 'full'], default='basic', help='نوع فحص الشبكة')
        network_parser.add_argument('--ports', help='المنافذ المراد فحصها (مثال: 80,443,8080 أو 1-1000)')
        
        # وحدة فحص الويب
        web_parser = subparsers.add_parser('web', help='وحدة فحص تطبيقات الويب')
        web_parser.add_argument('--scan', choices=['headers', 'vulns', 'full'], default='headers', help='نوع فحص الويب')
        web_parser.add_argument('--crawl', action='store_true', help='زحف الموقع واكتشاف الروابط')
        web_parser.add_argument('--depth', type=int, default=2, help='عمق الزحف (الافتراضي: 2)')
        
        # وحدة فحص DNS
        dns_parser = subparsers.add_parser('dns', help='وحدة فحص DNS')
        dns_parser.add_argument('--enum', action='store_true', help='تعداد سجلات DNS')
        dns_parser.add_argument('--zone-transfer', action='store_true', help='محاولة نقل منطقة DNS')
        
        # وحدة فحص SSL/TLS
        ssl_parser = subparsers.add_parser('ssl', help='وحدة فحص SSL/TLS')
        ssl_parser.add_argument('--check-cert', action='store_true', help='فحص تفاصيل الشهادة')
        ssl_parser.add_argument('--check-vulns', action='store_true', help='فحص ثغرات SSL/TLS')
        
        # وحدة فحص الملفات
        file_parser = subparsers.add_parser('file', help='وحدة فحص الملفات')
        file_parser.add_argument('--path', help='مسار الملف أو المجلد المراد فحصه')
        file_parser.add_argument('--hash', action='store_true', help='حساب قيم التجزئة للملفات')
        file_parser.add_argument('--malware', action='store_true', help='فحص البرمجيات الخبيثة')
        
        # وحدة التقارير
        report_parser = subparsers.add_parser('report', help='وحدة إنشاء التقارير')
        report_parser.add_argument('--format', choices=['txt', 'json', 'html', 'pdf'], default='txt', help='تنسيق التقرير')
        report_parser.add_argument('--input', help='ملف نتائج سابق لإنشاء تقرير منه')
        
        return parser.parse_args()
    
    def log(self, message, level='info'):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if level == 'info':
            print(f"{Fore.BLUE}[{timestamp}] [INFO] {message}{Style.RESET_ALL}")
        elif level == 'success':
            print(f"{Fore.GREEN}[{timestamp}] [SUCCESS] {message}{Style.RESET_ALL}")
        elif level == 'warning':
            print(f"{Fore.YELLOW}[{timestamp}] [WARNING] {message}{Style.RESET_ALL}")
        elif level == 'error':
            print(f"{Fore.RED}[{timestamp}] [ERROR] {message}{Style.RESET_ALL}")
        elif level == 'critical':
            print(f"{Back.RED}{Fore.WHITE}[{timestamp}] [CRITICAL] {message}{Style.RESET_ALL}")
    
    def normalize_url(self, url):
        if not url.startswith('http'):
            return f"http://{url}"
        return url
    
    def is_ip_address(self, target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def save_results(self):
        if not self.output_dir:
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.output_dir, f"saint_{self.target}_{timestamp}.json")
        
        # إضافة معلومات إضافية للنتائج
        self.results['scan_info'] = {
            'target': self.target,
            'start_time': datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration': f"{time.time() - self.start_time:.2f} seconds",
            'module': self.args.module if hasattr(self.args, 'module') else 'all'
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=4, default=str)
        
        self.log(f"تم حفظ النتائج في {filename}", 'success')
        return filename
    
    # وحدة فحص الشبكة
    def run_network_scan(self):
        self.log(f"بدء فحص الشبكة لـ {self.target}...")
        
        if not self.target:
            self.log("يجب تحديد الهدف باستخدام -t أو --target", 'error')
            return
        
        # تحديد نطاق المنافذ للفحص
        ports_to_scan = []
        if hasattr(self.args, 'ports') and self.args.ports:
            # تحليل نطاق المنافذ المحدد من المستخدم
            for port_range in self.args.ports.split(','):
                if '-' in port_range:
                    start, end = map(int, port_range.split('-'))
                    ports_to_scan.extend(range(start, end + 1))
                else:
                    ports_to_scan.append(int(port_range))
        else:
            # المنافذ الشائعة الافتراضية
            if hasattr(self.args, 'scan') and self.args.scan == 'full':
                ports_to_scan = list(range(1, 1001))  # فحص المنافذ من 1 إلى 1000
            else:
                # المنافذ الشائعة للفحص الأساسي
                ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        self.log(f"جاري فحص {len(ports_to_scan)} منفذ...")
        open_ports = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports_to_scan}
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, service = future.result()
                if is_open:
                    open_ports[port] = service
                    self.log(f"المنفذ {port} ({service}) مفتوح", 'success')
        
        self.results['network_scan'] = {
            'open_ports': open_ports,
            'total_ports_scanned': len(ports_to_scan),
            'total_open_ports': len(open_ports)
        }
        
        self.log(f"اكتمل فحص الشبكة. تم العثور على {len(open_ports)} منفذ مفتوح.", 'success')
        return open_ports
    
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout / 5)  # وقت أقل للمنافذ
            result = sock.connect_ex((self.target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return port, True, service
            return port, False, None
        except:
            return port, False, None
        finally:
            sock.close()
    
    # وحدة فحص تطبيقات الويب
    def run_web_scan(self):
        self.log(f"بدء فحص تطبيق الويب لـ {self.target}...")
        
        if not self.target:
            self.log("يجب تحديد الهدف باستخدام -t أو --target", 'error')
            return
        
        url = self.normalize_url(self.target)
        web_results = {}
        
        # فحص رؤوس HTTP
        if hasattr(self.args, 'scan') and (self.args.scan in ['headers', 'full']):
            headers, security_headers = self.check_http_headers(url)
            if headers:
                web_results['headers'] = headers
                web_results['security_headers'] = security_headers
        
        # فحص الثغرات الشائعة
        if hasattr(self.args, 'scan') and (self.args.scan in ['vulns', 'full']):
            vulnerabilities = self.check_common_web_vulns(url)
            web_results['vulnerabilities'] = vulnerabilities
        
        # زحف الموقع واكتشاف الروابط
        if hasattr(self.args, 'crawl') and self.args.crawl:
            depth = self.args.depth if hasattr(self.args, 'depth') else 2
            links = self.crawl_website(url, depth)
            web_results['crawled_links'] = links
        
        self.results['web_scan'] = web_results
        self.log("اكتمل فحص تطبيق الويب.", 'success')
        return web_results
    
    def check_http_headers(self, url):
        self.log(f"جاري فحص رؤوس HTTP لـ {url}...")
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            headers = dict(response.headers)
            
            # تحليل رؤوس الأمان
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'غير موجود'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'غير موجود'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'غير موجود'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'غير موجود'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'غير موجود'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'غير موجود'),
                'Feature-Policy': headers.get('Feature-Policy', 'غير موجود'),
                'Permissions-Policy': headers.get('Permissions-Policy', 'غير موجود')
            }
            
            # تقييم رؤوس الأمان
            missing_headers = [header for header, value in security_headers.items() if value == 'غير موجود']
            if missing_headers:
                self.log(f"رؤوس الأمان المفقودة: {', '.join(missing_headers)}", 'warning')
            
            self.log("تم فحص رؤوس HTTP بنجاح", 'success')
            return headers, security_headers
        except Exception as e:
            self.log(f"فشل في فحص رؤوس HTTP: {str(e)}", 'error')
            return None, None
    
    def check_common_web_vulns(self, url):
        self.log(f"جاري فحص الثغرات الشائعة لـ {url}...")
        vulnerabilities = []
        
        # قائمة بالمسارات الشائعة للفحص
        common_paths = [
            '/admin', '/login', '/wp-admin', '/phpinfo.php', '/test', '/backup',
            '/.git', '/.env', '/config', '/setup', '/install', '/debug'
        ]
        
        for path in common_paths:
            try:
                full_url = f"{url.rstrip('/')}{path}"
                response = requests.get(full_url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code < 400:  # تم العثور على المسار
                    vulnerabilities.append({
                        'type': 'exposed_path',
                        'url': full_url,
                        'status_code': response.status_code,
                        'risk': 'متوسط' if path in ['/admin', '/wp-admin', '/.git', '/.env'] else 'منخفض'
                    })
                    self.log(f"تم العثور على مسار محتمل: {full_url} (كود الحالة: {response.status_code})", 'warning')
            except Exception as e:
                if self.verbose:
                    self.log(f"خطأ أثناء فحص {full_url}: {str(e)}", 'error')
        
        # فحص XSS البسيط
        try:
            xss_payload = "<script>alert(1)</script>"
            xss_url = f"{url}?q={xss_payload}"
            response = requests.get(xss_url, timeout=self.timeout)
            
            if xss_payload in response.text:
                vulnerabilities.append({
                    'type': 'potential_xss',
                    'url': xss_url,
                    'risk': 'عالي'
                })
                self.log(f"تم اكتشاف ثغرة XSS محتملة في: {xss_url}", 'warning')
        except Exception as e:
            if self.verbose:
                self.log(f"خطأ أثناء فحص XSS: {str(e)}", 'error')
        
        self.log(f"اكتمل فحص الثغرات الشائعة. تم العثور على {len(vulnerabilities)} ثغرة محتملة.", 'success')
        return vulnerabilities
    
    def crawl_website(self, url, depth=2):
        self.log(f"جاري زحف الموقع {url} بعمق {depth}...")
        crawled_urls = set()
        to_crawl = {url}
        current_depth = 0
        
        while to_crawl and current_depth < depth:
            current_depth += 1
            self.log(f"زحف المستوى {current_depth}...")
            next_to_crawl = set()
            
            for current_url in to_crawl:
                if current_url in crawled_urls:
                    continue
                
                try:
                    response = requests.get(current_url, timeout=self.timeout)
                    crawled_urls.add(current_url)
                    
                    # استخراج الروابط من الصفحة
                    if response.status_code == 200:
                        # استخراج الروابط باستخدام تعبير منتظم بسيط
                        links = re.findall('href=[\'"]([^\'"]+)[\'"]', response.text)
                        
                        for link in links:
                            # تنظيف وتطبيع الرابط
                            if link.startswith('/'):
                                link = f"{url.rstrip('/')}{link}"
                            elif not link.startswith('http'):
                                link = f"{url.rstrip('/')}/{link}"
                            
                            # تجاهل الروابط الخارجية والبريد الإلكتروني وغيرها
                            if self.target in link and link not in crawled_urls:
                                next_to_crawl.add(link)
                except Exception as e:
                    if self.verbose:
                        self.log(f"خطأ أثناء زحف {current_url}: {str(e)}", 'error')
            
            to_crawl = next_to_crawl
            self.log(f"تم زحف {len(crawled_urls)} رابط حتى الآن. {len(next_to_crawl)} رابط في الانتظار.", 'info')
        
        self.log(f"اكتمل زحف الموقع. تم اكتشاف {len(crawled_urls)} رابط.", 'success')
        return list(crawled_urls)
    
    # وحدة فحص DNS
    def run_dns_scan(self):
        self.log(f"بدء فحص DNS لـ {self.target}...")
        
        if not self.target:
            self.log("يجب تحديد الهدف باستخدام -t أو --target", 'error')
            return
        
        # تجاهل فحص DNS إذا كان الهدف عنوان IP
        if self.is_ip_address(self.target):
            self.log("الهدف هو عنوان IP، تم تخطي فحص DNS", 'warning')
            return
        
        dns_results = {}
        
        # تعداد سجلات DNS
        if hasattr(self.args, 'enum') and self.args.enum:
            dns_records = self.enumerate_dns_records()
            dns_results['dns_records'] = dns_records
        
        # محاولة نقل منطقة DNS
        if hasattr(self.args, 'zone_transfer') and self.args.zone_transfer:
            zone_transfer = self.attempt_zone_transfer()
            dns_results['zone_transfer'] = zone_transfer
        
        self.results['dns_scan'] = dns_results
        self.log("اكتمل فحص DNS.", 'success')
        return dns_results
    
    def enumerate_dns_records(self):
        self.log(f"جاري تعداد سجلات DNS لـ {self.target}...")
        dns_records = {}
        
        # استخدام nslookup أو dig اعتمادًا على نظام التشغيل
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                if platform.system() == 'Windows':
                    cmd = f"nslookup -type={record_type} {self.target}"
                else:
                    cmd = f"dig {self.target} {record_type}"
                
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                output = stdout.decode('utf-8', errors='ignore')
                
                # تحليل مخرجات الأمر (تبسيط)
                dns_records[record_type] = output
                self.log(f"تم استعلام سجلات {record_type}", 'success')
            except Exception as e:
                self.log(f"فشل في استعلام سجلات {record_type}: {str(e)}", 'error')
        
        return dns_records
    
    def attempt_zone_transfer(self):
        self.log(f"محاولة نقل منطقة DNS لـ {self.target}...")
        
        try:
            # الحصول على خوادم الأسماء أولاً
            if platform.system() == 'Windows':
                cmd = f"nslookup -type=NS {self.target}"
            else:
                cmd = f"dig {self.target} NS"
            
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            ns_output = stdout.decode('utf-8', errors='ignore')
            
            # استخراج خوادم الأسماء (تبسيط)
            nameservers = []
            for line in ns_output.splitlines():
                if 'nameserver' in line.lower() or 'ns' in line.lower():
                    nameservers.append(line)
            
            # محاولة نقل المنطقة مع كل خادم أسماء
            zone_transfer_results = {}
            for ns in nameservers:
                try:
                    if platform.system() == 'Windows':
                        cmd = f"nslookup -type=AXFR {self.target} {ns}"
                    else:
                        cmd = f"dig @{ns} {self.target} AXFR"
                    
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    output = stdout.decode('utf-8', errors='ignore')
                    
                    zone_transfer_results[ns] = output
                    
                    if 'Transfer failed' not in output and 'communications error' not in output:
                        self.log(f"نجح نقل المنطقة مع {ns}!", 'critical')
                    else:
                        self.log(f"فشل نقل المنطقة مع {ns}", 'info')
                except Exception as e:
                    self.log(f"خطأ أثناء محاولة نقل المنطقة مع {ns}: {str(e)}", 'error')
            
            return zone_transfer_results
        except Exception as e:
            self.log(f"فشل في محاولة نقل منطقة DNS: {str(e)}", 'error')
            return None
    
    # وحدة فحص SSL/TLS
    def run_ssl_scan(self):
        self.log(f"بدء فحص SSL/TLS لـ {self.target}...")
        
        if not self.target:
            self.log("يجب تحديد الهدف باستخدام -t أو --target", 'error')
            return
        
        ssl_results = {}
        
        # فحص تفاصيل الشهادة
        if hasattr(self.args, 'check_cert') and self.args.check_cert:
            cert_info = self.check_ssl_certificate()
            ssl_results['certificate'] = cert_info
        
        # فحص ثغرات SSL/TLS
        if hasattr(self.args, 'check_vulns') and self.args.check_vulns:
            ssl_vulns = self.check_ssl_vulnerabilities()
            ssl_results['vulnerabilities'] = ssl_vulns
        
        self.results['ssl_scan'] = ssl_results
        self.log("اكتمل فحص SSL/TLS.", 'success')
        return ssl_results
    
    def check_ssl_certificate(self):
        self.log(f"جاري فحص شهادة SSL لـ {self.target}...")
        try:
            hostname = self.target
            if self.is_ip_address(hostname):
                self.log("تم تقديم عنوان IP، قد لا تعمل فحوصات SSL بشكل صحيح", 'warning')
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # استخراج معلومات الشهادة
                    issued_to = dict(cert['subject'][0])[('commonName',)] if cert.get('subject') else 'غير معروف'
                    issuer = dict(cert['issuer'][0])[('commonName',)] if cert.get('issuer') else 'غير معروف'
                    valid_from = cert.get('notBefore', 'غير معروف')
                    valid_until = cert.get('notAfter', 'غير معروف')
                    
                    ssl_info = {
                        'issued_to': issued_to,
                        'issuer': issuer,
                        'valid_from': valid_from,
                        'valid_until': valid_until,
                        'version': cert.get('version', 'غير معروف')
                    }
                    
                    # التحقق من صلاحية الشهادة
                    try:
                        from datetime import datetime
                        import ssl
                        import time
                        
                        not_after = ssl.cert_time_to_seconds(valid_until)
                        remaining_days = (not_after - time.time()) / (24 * 60 * 60)
                        
                        if remaining_days < 0:
                            self.log("شهادة SSL منتهية الصلاحية!", 'critical')
                            ssl_info['status'] = 'منتهية الصلاحية'
                        elif remaining_days < 30:
                            self.log(f"شهادة SSL ستنتهي قريبًا (خلال {remaining_days:.1f} يوم)", 'warning')
                            ssl_info['status'] = 'ستنتهي قريبًا'
                        else:
                            self.log("شهادة SSL صالحة", 'success')
                            ssl_info['status'] = 'صالحة'
                        
                        ssl_info['remaining_days'] = remaining_days
                    except Exception as e:
                        if self.verbose:
                            self.log(f"خطأ أثناء التحقق من صلاحية الشهادة: {str(e)}", 'error')
                    
                    self.log("تم فحص شهادة SSL بنجاح", 'success')
                    return ssl_info
        except Exception as e:
            self.log(f"فشل في فحص شهادة SSL: {str(e)}", 'error')
            return None
    
    def check_ssl_vulnerabilities(self):
        self.log(f"جاري فحص ثغرات SSL/TLS لـ {self.target}...")
        vulnerabilities = []
        
        # فحص بروتوكولات SSL/TLS القديمة
        protocols = {
            'SSLv2': {'supported': False, 'secure': False},
            'SSLv3': {'supported': False, 'secure': False},
            'TLSv1.0': {'supported': False, 'secure': False},
            'TLSv1.1': {'supported': False, 'secure': True},
            'TLSv1.2': {'supported': False, 'secure': True},
            'TLSv1.3': {'supported': False, 'secure': True}
        }
        
        # محاولة الاتصال باستخدام بروتوكولات مختلفة
        for protocol in protocols:
            try:
                if protocol == 'SSLv2':
                    context = ssl._create_unverified_context(ssl.PROTOCOL_SSLv23)
                    context.options &= ~ssl.OP_NO_SSLv2
                elif protocol == 'SSLv3':
                    context = ssl._create_unverified_context(ssl.PROTOCOL_SSLv23)
                    context.options &= ~ssl.OP_NO_SSLv3
                elif protocol == 'TLSv1.0':
                    context = ssl._create_unverified_context(ssl.PROTOCOL_TLSv1)
                elif protocol == 'TLSv1.1':
                    context = ssl._create_unverified_context(ssl.PROTOCOL_TLSv1_1)
                elif protocol == 'TLSv1.2':
                    context = ssl._create_unverified_context(ssl.PROTOCOL_TLSv1_2)
                else:  # TLSv1.3
                    # قد لا يكون مدعومًا في جميع إصدارات Python
                    try:
                        context = ssl._create_unverified_context(ssl.PROTOCOL_TLS)
                        context.minimum_version = ssl.TLSVersion.TLSv1_3
                    except AttributeError:
                        continue
                
                with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        protocols[protocol]['supported'] = True
                        self.log(f"البروتوكول {protocol} مدعوم", 'info')
                        
                        if not protocols[protocol]['secure']:
                            vulnerabilities.append({
                                'type': 'insecure_protocol',
                                'protocol': protocol,
                                'risk': 'عالي' if protocol in ['SSLv2', 'SSLv3'] else 'متوسط'
                            })
                            self.log(f"تم اكتشاف بروتوكول غير آمن: {protocol}", 'warning')
            except Exception as e:
                if self.verbose:
                    self.log(f"البروتوكول {protocol} غير مدعوم: {str(e)}", 'info')
        
        # فحص الخوارزميات الضعيفة (تبسيط)
        try:
            if platform.system() == 'Windows':
                cmd = f"echo | openssl s_client -connect {self.target}:443 -cipher LOW:NULL:EXP"
            else:
                cmd = f"echo | openssl s_client -connect {self.target}:443 -cipher LOW:NULL:EXP"
            
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            
            if 'Cipher is' in output and not 'Cipher is (NONE)' in output:
                cipher = re.search(r'Cipher is ([^\s]+)', output)
                if cipher:
                    vulnerabilities.append({
                        'type': 'weak_cipher',
                        'cipher': cipher.group(1),
                        'risk': 'عالي'
                    })
                    self.log(f"تم اكتشاف خوارزمية تشفير ضعيفة: {cipher.group(1)}", 'warning')
        except Exception as e:
            if self.verbose:
                self.log(f"خطأ أثناء فحص خوارزميات التشفير: {str(e)}", 'error')
        
        self.log(f"اكتمل فحص ثغرات SSL/TLS. تم العثور على {len(vulnerabilities)} ثغرة.", 'success')
        return vulnerabilities
    
    # وحدة فحص الملفات
    def run_file_scan(self):
        self.log("بدء فحص الملفات...")
        
        if not hasattr(self.args, 'path') or not self.args.path:
            self.log("يجب تحديد مسار الملف أو المجلد باستخدام --path", 'error')
            return
        
        file_path = self.args.path
        if not os.path.exists(file_path):
            self.log(f"المسار غير موجود: {file_path}", 'error')
            return
        
        file_results = {}
        
        # حساب قيم التجزئة للملفات
        if hasattr(self.args, 'hash') and self.args.hash:
            file_hashes = self.calculate_file_hashes(file_path)
            file_results['hashes'] = file_hashes
        
        # فحص البرمجيات الخبيثة (تبسيط)
        if hasattr(self.args, 'malware') and self.args.malware:
            malware_scan = self.scan_for_malware(file_path)
            file_results['malware_scan'] = malware_scan
        
        self.results['file_scan'] = file_results
        self.log("اكتمل فحص الملفات.", 'success')
        return file_results
    
    def calculate_file_hashes(self, path):
        self.log(f"جاري حساب قيم التجزئة للملفات في {path}...")
        file_hashes = {}
        
        if os.path.isfile(path):
            files = [path]
        else:
            files = [os.path.join(root, file) for root, _, files in os.walk(path) for file in files]
        
        for file_path in files:
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    md5_hash = hashlib.md5(content).hexdigest()
                    sha1_hash = hashlib.sha1(content).hexdigest()
                    sha256_hash = hashlib.sha256(content).hexdigest()
                    
                    file_hashes[file_path] = {
                        'md5': md5_hash,
                        'sha1': sha1_hash,
                        'sha256': sha256_hash,
                        'size': os.path.getsize(file_path)
                    }
                    
                    if self.verbose:
                        self.log(f"تم حساب قيم التجزئة لـ {file_path}", 'info')
            except Exception as e:
                self.log(f"فشل في حساب قيم التجزئة لـ {file_path}: {str(e)}", 'error')
        
        self.log(f"تم حساب قيم التجزئة لـ {len(file_hashes)} ملف.", 'success')
        return file_hashes
    
    def scan_for_malware(self, path):
        self.log(f"جاري فحص البرمجيات الخبيثة في {path}...")
        malware_results = {
            'suspicious_files': [],
            'scan_summary': {}
        }
        
        # قائمة بأنماط الملفات المشبوهة (تبسيط)
        suspicious_patterns = [
            r'(?i)\b(backdoor|trojan|virus|malware|exploit)\b',
            r'(?i)\.exe$|\.dll$|\.bat$|\.cmd$|\.ps1$|\.vbs$',
            r'(?i)eval\(|exec\(|system\(|shell_exec\(|passthru\(|\`|\$_GET|\$_POST',
            r'(?i)base64_decode\(|fromCharCode|String\.fromCharCode'
        ]
        
        if os.path.isfile(path):
            files = [path]
        else:
            files = [os.path.join(root, file) for root, _, files in os.walk(path) for file in files]
        
        for file_path in files:
            try:
                # تجاهل الملفات الكبيرة
                if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10 ميجابايت
                    if self.verbose:
                        self.log(f"تم تخطي {file_path} (حجم كبير جدًا)", 'info')
                    continue
                
                # فحص محتوى الملف
                with open(file_path, 'rb') as f:
                    try:
                        content = f.read().decode('utf-8', errors='ignore')
                        
                        for pattern in suspicious_patterns:
                            matches = re.findall(pattern, content)
                            if matches:
                                malware_results['suspicious_files'].append({
                                    'file': file_path,
                                    'pattern': pattern,
                                    'matches': matches[:10]  # الحد من عدد التطابقات المعروضة
                                })
                                self.log(f"تم العثور على نمط مشبوه في {file_path}: {pattern}", 'warning')
                                break
                    except Exception as e:
                        if self.verbose:
                            self.log(f"خطأ أثناء قراءة {file_path}: {str(e)}", 'error')
            except Exception as e:
                self.log(f"فشل في فحص {file_path}: {str(e)}", 'error')
        
        malware_results['scan_summary'] = {
            'total_files': len(files),
            'suspicious_files': len(malware_results['suspicious_files'])
        }
        
        self.log(f"اكتمل فحص البرمجيات الخبيثة. تم العثور على {len(malware_results['suspicious_files'])} ملف مشبوه.", 'success')
        return malware_results
    
    # وحدة إنشاء التقارير
    def generate_report(self):
        self.log("جاري إنشاء التقرير...")
        
        # استخدام نتائج سابقة إذا تم تحديدها
        if hasattr(self.args, 'input') and self.args.input:
            try:
                with open(self.args.input, 'r', encoding='utf-8') as f:
                    self.results = json.load(f)
                self.log(f"تم تحميل النتائج من {self.args.input}", 'success')
            except Exception as e:
                self.log(f"فشل في تحميل النتائج: {str(e)}", 'error')
                return
        
        # تحديد تنسيق التقرير
        report_format = 'txt'
        if hasattr(self.args, 'format'):
            report_format = self.args.format
        
        # إنشاء التقرير
        if report_format == 'txt':
            report = self.generate_txt_report()
        elif report_format == 'json':
            report = json.dumps(self.results, ensure_ascii=False, indent=4, default=str)
        elif report_format == 'html':
            report = self.generate_html_report()
        elif report_format == 'pdf':
            self.log("تنسيق PDF غير مدعوم حاليًا، سيتم استخدام HTML بدلاً من ذلك", 'warning')
            report = self.generate_html_report()
        else:
            self.log(f"تنسيق التقرير غير معروف: {report_format}", 'error')
            return
        
        # حفظ التقرير
        if self.output_dir:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            target_name = self.target if self.target else 'report'
            filename = os.path.join(self.output_dir, f"saint_{target_name}_{timestamp}.{report_format}")
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            
            self.log(f"تم حفظ التقرير في {filename}", 'success')
        else:
            print("\n" + "=" * 80)
            print("التقرير:")
            print("=" * 80)
            print(report)
        
        return report
    
    def generate_txt_report(self):
        report = []
        report.append("=" * 80)
        report.append("SAINT Security Suite - تقرير الفحص الأمني")
        report.append("=" * 80)
        report.append(f"الهدف: {self.target if self.target else 'غير محدد'}")
        
        if 'scan_info' in self.results:
            report.append(f"تاريخ البدء: {self.results['scan_info'].get('start_time', 'غير معروف')}")
            report.append(f"تاريخ الانتهاء: {self.results['scan_info'].get('end_time', 'غير معروف')}")
            report.append(f"المدة: {self.results['scan_info'].get('duration', 'غير معروف')}")
            report.append(f"الوحدة: {self.results['scan_info'].get('module', 'غير معروف')}")
        
        report.append("\n" + "=" * 80)
        report.append("ملخص النتائج:")
        report.append("=" * 80)
        
        # ملخص فحص الشبكة
        if 'network_scan' in self.results:
            report.append("\nنتائج فحص الشبكة:")
            report.append("-" * 40)
            
            if 'open_ports' in self.results['network_scan']:
                open_ports = self.results['network_scan']['open_ports']
                report.append(f"المنافذ المفتوحة: {len(open_ports)}")
                
                for port, service in open_ports.items():
                    report.append(f"  - المنفذ {port}: {service}")
        
        # ملخص فحص الويب
        if 'web_scan' in self.results:
            report.append("\nنتائج فحص تطبيق الويب:")
            report.append("-" * 40)
            
            if 'security_headers' in self.results['web_scan']:
                security_headers = self.results['web_scan']['security_headers']
                report.append("رؤوس الأمان:")
                
                for header, value in security_headers.items():
                    report.append(f"  - {header}: {value}")
            
            if 'vulnerabilities' in self.results['web_scan']:
                vulnerabilities = self.results['web_scan']['vulnerabilities']
                report.append(f"\nالثغرات المكتشفة: {len(vulnerabilities)}")
                
                for vuln in vulnerabilities:
                    report.append(f"  - النوع: {vuln.get('type', 'غير معروف')}")
                    report.append(f"    الرابط: {vuln.get('url', 'غير معروف')}")
                    report.append(f"    مستوى الخطورة: {vuln.get('risk', 'غير معروف')}")
        
        # ملخص فحص SSL
        if 'ssl_scan' in self.results:
            report.append("\nنتائج فحص SSL/TLS:")
            report.append("-" * 40)
            
            if 'certificate' in self.results['ssl_scan']:
                cert = self.results['ssl_scan']['certificate']
                report.append("معلومات الشهادة:")
                report.append(f"  - صادرة لـ: {cert.get('issued_to', 'غير معروف')}")
                report.append(f"  - صادرة من: {cert.get('issuer', 'غير معروف')}")
                report.append(f"  - صالحة من: {cert.get('valid_from', 'غير معروف')}")
                report.append(f"  - صالحة حتى: {cert.get('valid_until', 'غير معروف')}")
                report.append(f"  - الحالة: {cert.get('status', 'غير معروف')}")
            
            if 'vulnerabilities' in self.results['ssl_scan']:
                ssl_vulns = self.results['ssl_scan']['vulnerabilities']
                report.append(f"\nثغرات SSL/TLS: {len(ssl_vulns)}")
                
                for vuln in ssl_vulns:
                    report.append(f"  - النوع: {vuln.get('type', 'غير معروف')}")
                    if 'protocol' in vuln:
                        report.append(f"    البروتوكول: {vuln['protocol']}")
                    if 'cipher' in vuln:
                        report.append(f"    خوارزمية التشفير: {vuln['cipher']}")
                    report.append(f"    مستوى الخطورة: {vuln.get('risk', 'غير معروف')}")
        
        # ملخص فحص DNS
        if 'dns_scan' in self.results:
            report.append("\nنتائج فحص DNS:")
            report.append("-" * 40)
            
            if 'dns_records' in self.results['dns_scan']:
                dns_records = self.results['dns_scan']['dns_records']
                report.append("سجلات DNS:")
                
                for record_type, records in dns_records.items():
                    report.append(f"  - {record_type}:")
                    # تبسيط عرض السجلات
                    record_lines = records.split('\n')[:5]
                    for line in record_lines:
                        if line.strip():
                            report.append(f"    {line.strip()}")
                    if len(records.split('\n')) > 5:
                        report.append(f"    ... ({len(records.split('\n')) - 5} سطر إضافي)")
        
        # ملخص فحص الملفات
        if 'file_scan' in self.results:
            report.append("\nنتائج فحص الملفات:")
            report.append("-" * 40)
            
            if 'malware_scan' in self.results['file_scan']:
                malware_scan = self.results['file_scan']['malware_scan']
                summary = malware_scan.get('scan_summary', {})
                report.append(f"إجمالي الملفات التي تم فحصها: {summary.get('total_files', 0)}")
                report.append(f"الملفات المشبوهة: {summary.get('suspicious_files', 0)}")
                
                if malware_scan.get('suspicious_files'):
                    report.append("\nالملفات المشبوهة:")
                    for file_info in malware_scan['suspicious_files'][:10]:  # عرض أول 10 ملفات فقط
                        report.append(f"  - {file_info.get('file', 'غير معروف')}")
                    
                    if len(malware_scan['suspicious_files']) > 10:
                        report.append(f"  ... و {len(malware_scan['suspicious_files']) - 10} ملف آخر")
        
        report.append("\n" + "=" * 80)
        report.append(f"تم إنشاء التقرير بواسطة SAINT Security Suite v{self.version}")
        report.append(f"تم تطويره بواسطة: {self.author}")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def generate_html_report(self):
        # قالب HTML بسيط للتقرير
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html dir='rtl' lang='ar'>")
        html.append("<head>")
        html.append("<meta charset='UTF-8'>")
        html.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("<title>SAINT Security Suite - تقرير الفحص الأمني</title>")
        html.append("<style>")
        html.append("body { font-family: Arial, sans-serif; margin: 0; padding: 20px; direction: rtl; }")
        html.append("h1, h2, h3 { color: #2c3e50; }")
        html.append(".container { max-width: 1200px; margin: 0 auto; }")
        html.append(".header { background-color: #3498db; color: white; padding: 20px; text-align: center; border-radius: 5px; }")
        html.append(".section { background-color: #f9f9f9; padding: 15px; margin: 15px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }")
        html.append(".info { display: flex; flex-wrap: wrap; }")
        html.append(".info-item { flex: 1; min-width: 250px; margin: 5px; }")
        html.append(".success { color: #27ae60; }")
        html.append(".warning { color: #f39c12; }")
        html.append(".danger { color: #e74c3c; }")
        html.append(".footer { text-align: center; margin-top: 30px; color: #7f8c8d; font-size: 0.9em; }")
        html.append("table { width: 100%; border-collapse: collapse; margin: 15px 0; }")
        html.append("th, td { padding: 8px; text-align: right; border-bottom: 1px solid #ddd; }")
        html.append("th { background-color: #f2f2f2; }")
        html.append("tr:hover { background-color: #f5f5f5; }")
        html.append(".risk-low { background-color: #d4efdf; }")
        html.append(".risk-medium { background-color: #fdebd0; }")
        html.append(".risk-high { background-color: #f5b7b1; }")
        html.append(".risk-critical { background-color: #f1948a; }")
        html.append("</style>")
        
        html.append("</head>")
        html.append("<body>")
        html.append("<div class='container'>")
        
        # رأس التقرير
        html.append("<div class='header'>")
        html.append("<h1>SAINT Security Suite - تقرير الفحص الأمني</h1>")
        html.append(f"<p>الهدف: {self.target if self.target else 'غير محدد'}</p>")
        html.append("</div>")
        
        # معلومات الفحص
        html.append("<div class='section'>")
        html.append("<h2>معلومات الفحص</h2>")
        html.append("<div class='info'>")
        
        if 'scan_info' in self.results:
            scan_info = self.results['scan_info']
            html.append("<div class='info-item'>")
            html.append(f"<p><strong>تاريخ البدء:</strong> {scan_info.get('start_time', 'غير معروف')}</p>")
            html.append(f"<p><strong>تاريخ الانتهاء:</strong> {scan_info.get('end_time', 'غير معروف')}</p>")
            html.append(f"<p><strong>المدة:</strong> {scan_info.get('duration', 'غير معروف')}</p>")
            html.append(f"<p><strong>الوحدة:</strong> {scan_info.get('module', 'غير معروف')}</p>")
            html.append("</div>")
        
        html.append("</div>")
        html.append("</div>")
        
        # نتائج فحص الشبكة
        if 'network_scan' in self.results:
            html.append("<div class='section'>")
            html.append("<h2>نتائج فحص الشبكة</h2>")
            
            if 'open_ports' in self.results['network_scan']:
                open_ports = self.results['network_scan']['open_ports']
                html.append(f"<h3>المنافذ المفتوحة: {len(open_ports)}</h3>")
                
                if open_ports:
                    html.append("<table>")
                    html.append("<tr><th>المنفذ</th><th>الخدمة</th></tr>")
                    
                    for port, service in open_ports.items():
                        html.append(f"<tr><td>{port}</td><td>{service}</td></tr>")
                    
                    html.append("</table>")
                else:
                    html.append("<p>لم يتم العثور على منافذ مفتوحة.</p>")
            
            html.append("</div>")
        
        # نتائج فحص الويب
        if 'web_scan' in self.results:
            html.append("<div class='section'>")
            html.append("<h2>نتائج فحص تطبيق الويب</h2>")
            
            if 'security_headers' in self.results['web_scan']:
                security_headers = self.results['web_scan']['security_headers']
                html.append("<h3>رؤوس الأمان</h3>")
                
                html.append("<table>")
                html.append("<tr><th>الرأس</th><th>القيمة</th></tr>")
                
                for header, value in security_headers.items():
                    html.append(f"<tr><td>{header}</td><td>{value}</td></tr>")
                
                html.append("</table>")
            
            if 'vulnerabilities' in self.results['web_scan']:
                vulnerabilities = self.results['web_scan']['vulnerabilities']
                html.append(f"<h3>الثغرات المكتشفة: {len(vulnerabilities)}</h3>")
                
                if vulnerabilities:
                    html.append("<table>")
                    html.append("<tr><th>النوع</th><th>الرابط</th><th>مستوى الخطورة</th></tr>")
                    
                    for vuln in vulnerabilities:
                        risk_class = f"risk-{vuln.get('risk', 'low').lower()}"
                        html.append(f"<tr class='{risk_class}'>")
                        html.append(f"<td>{vuln.get('type', 'غير معروف')}</td>")
                        html.append(f"<td>{vuln.get('url', 'غير معروف')}</td>")
                        html.append(f"<td>{vuln.get('risk', 'غير معروف')}</td>")
                        html.append("</tr>")
                    
                    html.append("</table>")
                else:
                    html.append("<p>لم يتم العثور على ثغرات.</p>")
            
            html.append("</div>")
        
        # نتائج فحص SSL
        if 'ssl_scan' in self.results:
            html.append("<div class='section'>")
            html.append("<h2>نتائج فحص SSL/TLS</h2>")
            
            if 'certificate' in self.results['ssl_scan']:
                cert = self.results['ssl_scan']['certificate']
                html.append("<h3>معلومات الشهادة</h3>")
                
                html.append("<table>")
                html.append("<tr><th>المعلومة</th><th>القيمة</th></tr>")
                html.append(f"<tr><td>صادرة لـ</td><td>{cert.get('issued_to', 'غير معروف')}</td></tr>")
                html.append(f"<tr><td>صادرة من</td><td>{cert.get('issuer', 'غير معروف')}</td></tr>")
                html.append(f"<tr><td>صالحة من</td><td>{cert.get('valid_from', 'غير معروف')}</td></tr>")
                html.append(f"<tr><td>صالحة حتى</td><td>{cert.get('valid_until', 'غير معروف')}</td></tr>")
                html.append(f"<tr><td>الحالة</td><td>{cert.get('status', 'غير معروف')}</td></tr>")
                html.append("</table>")
            
            if 'vulnerabilities' in self.results['ssl_scan']:
                ssl_vulns = self.results['ssl_scan']['vulnerabilities']
                html.append(f"<h3>ثغرات SSL/TLS: {len(ssl_vulns)}</h3>")
                
                if ssl_vulns:
                    html.append("<table>")
                    html.append("<tr><th>النوع</th><th>البروتوكول</th><th>خوارزمية التشفير</th><th>مستوى الخطورة</th></tr>")
                    
                    for vuln in ssl_vulns:
                        risk_class = f"risk-{vuln.get('risk', 'low').lower()}"
                        html.append(f"<tr class='{risk_class}'>")
                        html.append(f"<td>{vuln.get('type', 'غير معروف')}</td>")
                        html.append(f"<td>{vuln.get('protocol', 'غير معروف')}</td>")
                        html.append(f"<td>{vuln.get('cipher', 'غير معروف')}</td>")
                        html.append(f"<td>{vuln.get('risk', 'غير معروف')}</td>")
                        html.append("</tr>")
                    
                    html.append("</table>")
                else:
                    html.append("<p>لم يتم العثور على ثغرات SSL/TLS.</p>")
            
            html.append("</div>")
        
        # تذييل التقرير
        html.append("<div class='footer'>")
        html.append(f"<p>تم إنشاء التقرير بواسطة SAINT Security Suite v{self.version}</p>")
        html.append(f"<p>تم تطويره بواسطة: {self.author}</p>")
        html.append("</div>")
        
        html.append("</div>")
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)
    
    def generate_json_report(self):
        # إنشاء نسخة من النتائج للتقرير
        report_data = self.results.copy()
        
        # إضافة معلومات إضافية
        report_data['report_info'] = {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'generator': f"SAINT Security Suite v{self.version}",
            'author': self.author
        }
        
        return json.dumps(report_data, ensure_ascii=False, indent=4, default=str)


def main():
    try:
        saint = SAINTSecuritySuite()
        
        if not saint.args.target and not saint.args.module == 'report':
            print(f"{Fore.RED}[!] خطأ: يجب تحديد الهدف باستخدام -t أو --target{Style.RESET_ALL}")
            sys.exit(1)
        
        # تشغيل الوحدة المناسبة بناءً على اختيار المستخدم
        if saint.args.module == 'network':
            saint.run_network_scan()
        elif saint.args.module == 'web':
            saint.run_web_scan()
        elif saint.args.module == 'dns':
            saint.run_dns_scan()
        elif saint.args.module == 'ssl':
            saint.run_ssl_scan()
        elif saint.args.module == 'file':
            saint.run_file_scan()
        elif saint.args.module == 'report':
            saint.run_report_generation()
        else:
            print(f"{Fore.RED}[!] خطأ: يجب تحديد وحدة الفحص{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] الوحدات المتاحة: network, web, dns, ssl, file, report{Style.RESET_ALL}")
            sys.exit(1)
        
        # حفظ النتائج
        saint.save_results()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] تم إيقاف الفحص بواسطة المستخدم{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] حدث خطأ: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()