import  os.path
import sys
import re
from subprocess import Popen, PIPE


def checkZoneTransfer(domains, dnsservers):
    success = False
    for domain in domains:
        print("    [+] {}".format(domain))
        for dns in dnsservers:
            dns = '@' + dns
            process = Popen(['dig', 'axfr', domain, dns], stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            if re.findall('Transfer failed', stdout.decode('utf-8')):
                print("zone transfer failed")
            else:
                success = True
                print("[+] domain {} {} is vulnerable to zone transfer".format(domains, dns))
            # save to log
    return success

def ReadListFromFile(path):
    arr = []
    try:
        with open(path) as f:
            for line in f:
                # print(line)
                arr.append(line.rstrip("\n\r"))

        return arr
    except Exception:
        print("[x] Error reading file. Exiting")
        exit(1)
    finally:
        f.close()


def main():
    print("[+] Loading domains from list...")
    domains = ReadListFromFile(sys.argv[1])

    print("[+] Loading DNS servers from list...")
    dnsservers = ReadListFromFile(sys.argv[2])

    print("[+] Checking zone transfer")
    result = checkZoneTransfer(domains, dnsservers)

    print("[+] Test results")
    if result:
        print("[+] True")
    else:
        print("[-] False")


if __name__ == "__main__":
    main()
