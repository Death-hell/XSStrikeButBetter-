import argparse
import subprocess
import os

def run_arjun(url):
    print(f"[+] Running Arjun on: {url}")
    output_file = "arjun_output.txt"
    try:
        subprocess.run(
            ["python3", "tools/Arjun/arjun", "-u", url, "-m", "GET", "--stable", "-oT", output_file],
            check=True
        )

        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                params = [line.strip() for line in f if line.strip()]
            print(f"[+] Found {len(params)} parameter(s): {params}")
            return params
        else:
            print("[!] Arjun did not generate output.")
            return []

    except Exception as e:
        print(f"[!] Arjun failed: {e}")
        return []
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Arjun and extract parameters for XSStrike")
    parser.add_argument("url", help="Target URL (e.g., https://example.com/page)")
    args = parser.parse_args()

    parameters = run_arjun(args.url)

    if parameters:
        print("[+] Launching XSStrike with extracted parameters...")
        subprocess.run(["python3", "xsstrike.py", "-u", args.url, "--fuzzer"])
    else:
        print("[!] No parameters found.")
