from subprocess import Popen, PIPE
import re
import sys
from datetime import datetime
import os.path

def ReadDomainListFromFile(path):
    arr = []
    try:
        with open(path) as f:
            for line in f:
                print(line)
                arr.append(line.rstrip("\n\r"))

        return arr
    except Exception:
        print("[x] Error reading file. Exiting")
        exit(1)
    finally:
        f.close()


def CheckDmarcRecord(domain_name):
    domain_name2 = '_dmarc.' + domain_name
    #print(domain_name2)
    process = Popen(['dig', 'txt', domain_name2], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()

    if re.findall('DMARC', stdout):
        policy = ['none', 'reject', 'quarantine']
        for i in policy:
            if re.findall(i, stdout):
                print("    [+] DMARC record found - " + i)
                return i

    else:
        print("    [+] DMARC record not found")
        return False


def CheckSpfRecord(domain_name):
    #print(domain_name)
    process = Popen(['dig', '-t', 'txt', domain_name], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    #print(stdout)
    if re.findall('spf', stdout):
        if re.findall('~all', stdout):
            #Soft-fail
            print("    [+] SPF record found, soft fail")
            return 1

        elif re.findall('-all', stdout):
            #hard fail
            print("    [+] SPF record found, hard fail")
            return 2
        else:
            print("    [+] all mechanism not found")

    else:
        print("    [+] SPF record not found")
        return False


def WriteToTable(file_object, string):
    file_object.write(string)


def CreateOutputFile(file_name):
    # Create the file.
    if sys.argv[2]:
        print(sys.argv[2])
        path = sys.argv[2] + "_" + datetime.now().strftime('%Y%m%d%H') + ".html"
        html_file = OpenOutputFile(path)
        if not os.path.isfile(path):
            print("[*] Error - Output file can't be found")
            exit(1)
    return html_file


def OpenOutputFile(path):
    html_file = open(path, "w")
    return html_file


def WriteToHtmlTable(domains_list, output_file):

    html_str = """
    <html>
    <head>
        <title>Email Spoofing Check</title>
    </head>
        <body>
            <table border="1">
                <tr>
                    <td>Domain</td>
                    <td>SPF</td>
                    <td>DMARC</td>
                </tr>
    """
    WriteToTable(output_file, html_str)

    for domain in domains_list:
        WriteToTable(output_file, "<tr>")
        WriteToTable(output_file, "<td>" + domain + "</td>")

        print("[+] Checking domain " + domain + ":")

        record_result = CheckSpfRecord(domain)

        if record_result and record_result == 1:
            # soft fail
            WriteToTable(output_file, "<td>V [Soft]</td>")

        if record_result and record_result == 2:
            # hard fail
            WriteToTable(output_file, "<td>V [Hard]</td>")

        elif not record_result:
            # no SPF
            WriteToTable(output_file, "<td>X</td>")

        record_result = CheckDmarcRecord(domain)
        if record_result:
            # value holds the policy
            WriteToTable(output_file, "<td>V ["+record_result+"]</td>")

        else:
            # dmarc not found
            WriteToTable(output_file, "<td>X</td>")

        WriteToTable(output_file, "</tr>")

    WriteToTable(output_file, "</body></html>")


def help():
    if len(sys.argv) < 4:
        print("Usage: ./emailsec.py [domains_list] [Output_file_path] [Output Type]")
        print("Output type: HTML, JSON")
        print("Example: ./emailsec.py /tmp/domains.txt /tmp/output html")
        exit(1)

def main():
    help()

    domains = ReadDomainListFromFile(sys.argv[1])

    if sys.argv[3].lower == 'html':
        html_file = CreateOutputFile(sys.argv[2])

        WriteToHtmlTable(domains, html_file)
        html_file.close()

    elif sys.argv[3].lower == 'json':
        pass


if __name__ == "__main__":
    main()