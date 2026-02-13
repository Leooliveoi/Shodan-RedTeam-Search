import requests
import argparse
import json
import sys
import re
from packaging import version
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()

def get_preliminary_risk(cvss, epss, kev, ransom):
    cvss, epss = float(cvss or 0.0), float(epss or 0.0)
    if kev or ransom: return "[bold red]CRITICAL (Active)[/bold red]"
    if epss > 0.80 and cvss >= 7.0: return "[bold red]CRITICAL (High Prob)[/bold red]"
    if cvss >= 9.0 or epss > 0.50: return "[bold orange1]HIGH[/bold orange1]"
    return "[yellow]MEDIUM[/yellow]"

def is_vulnerable_lineage(target_ver, summary):
    if not target_ver: return True
    try:
        target = version.parse(target_ver)
        match_fix = re.search(r"(?:before|fixed in|prior to|up to) ([\d\.]+)", summary.lower())
        if match_fix:
            fix_ver = version.parse(match_fix.group(1))
            if target < fix_ver:
                branch_limit = re.search(r"(\d)\.x (?:only|specifically)", summary.lower())
                if branch_limit and target.major < int(branch_limit.group(1)): return False
                return True
        return False
    except: return True

def display_detailed_cve(cve_data):
    """Exibe todos os campos disponíveis para uma única CVE."""
    console.print(Panel(f"[bold cyan]Full Intel Report:[/bold cyan] {cve_data.get('cve_id')}", expand=False))

    # Tabela de Informações Básicas e Risco
    risk_table = Table(show_header=False, box=None)
    risk_table.add_column("Key", style="bold")
    risk_table.add_column("Value")

    cvss = cve_data.get('cvss_v3') or cve_data.get('cvss') or "N/A"
    epss = f"{float(cve_data.get('epss', 0))*100:.4f}%"
    risk = get_preliminary_risk(cve_data.get('cvss'), cve_data.get('epss'), cve_data.get('is_kev'), cve_data.get('ransomware_campaign'))

    risk_table.add_row("Preliminary Risk:", risk)
    risk_table.add_row("CVSS Score:", str(cvss))
    risk_table.add_row("EPSS Score:", epss)
    risk_table.add_row("EPSS Percentile:", f"{float(cve_data.get('ranking_epss', 0))*100:.2f}%")
    risk_table.add_row("CISA KEV:", "[bold red]YES[/bold red]" if cve_data.get('is_kev') else "No")
    risk_table.add_row("Ransomware:", "[bold red]YES[/bold red]" if cve_data.get('ransomware_campaign') else "No")
    risk_table.add_row("Published:", cve_data.get('published_at', 'N/A'))
    risk_table.add_row("Last Modified:", cve_data.get('last_modified_at', 'N/A'))

    console.print(risk_table)

    # Resumo
    console.print(Panel(cve_data.get('summary', 'No summary available'), title="Summary", border_style="dim"))

    # Referências
    if cve_data.get('references'):
        ref_table = Table(title="Technical References", title_justify="left", box=None)
        ref_table.add_column("URL", style="blue underline")
        for ref in cve_data.get('references'):
            ref_table.add_row(ref)
        console.print(ref_table)

def fetch_discovery(product, ver_str=None):
    base_url = "https://cvedb.shodan.io/cves"
    if ver_str:
        vendors = [product, "httpd", "apache", "nginx", "f5", "getbootstrap"]
        for v in vendors:
            cpe = f"cpe:2.3:a:{v}:{product}:{ver_str}"
            try:
                resp = requests.get(base_url, params={"cpe23": cpe}, timeout=10)
                if resp.status_code == 200:
                    data = resp.json().get('cves', [])
                    vetted = [c for c in data if is_vulnerable_lineage(ver_str, c.get('summary', ''))]
                    if vetted: return vetted, f"FORCE_CPE ({v})"
            except: continue
    else:
        try:
            resp = requests.get(base_url, params={"product": product}, timeout=10)
            if resp.status_code == 200: return resp.json().get('cves', []), "GENERAL_SEARCH"
        except: pass
    return [], None

def main():
    parser = argparse.ArgumentParser(description="OiSecuritu - Shodan Red Team Search - v0.1")
    parser.add_argument("-p", "--product", help="Product ID")
    parser.add_argument("-v", "--version", help="Version")
    parser.add_argument("-c", "--cve", help="Direct CVE search (Full Details)")
    parser.add_argument("-o", "--output", help="Output filename")
    parser.add_argument("-f", "--format", choices=['json'], help="Output format")
    args = parser.parse_args()

    if args.cve:
        url = f"https://cvedb.shodan.io/cve/{args.cve}"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                display_detailed_cve(resp.json())
                if args.output:
                    with open(args.output, 'w') as f: json.dump(resp.json(), f, indent=4)
            else:
                console.print(f"[red]CVE {args.cve} not found.[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    elif args.product:
        results, method = fetch_discovery(args.product, args.version)
        if not results:
            console.print("[red]No results.[/red]")
            return
        # Exibe tabela resumida no modo Discovery
        table = Table(title=f"Discovery: {args.product} - Method: {method}")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Risk")
        table.add_column("Summary", ratio=1)
        for item in results[:15]:
            risk = get_preliminary_risk(item.get('cvss'), item.get('epss'), item.get('is_kev'), item.get('ransomware_campaign'))
            table.add_row(item.get('cve_id'), risk, item.get('summary', '')[:100] + "...")
        console.print(table)

if __name__ == "__main__":
    main()
