# -*- coding: utf-8 -*-
import json
import csv

cvrf = {}

with open('C:/temp/jul2018.json') as file:
    cvrf = json.loads(file.read())

#print len(cvrf['ProductTree']['Branch'][0])
#print cvrf['ProductTree']['Branch'][0]['Name']
products = {}
for branch in cvrf['ProductTree']['Branch'][0]['Items']:
    for product in branch['Items']:
        products[product['ProductID']] = { 'name' : unicode(product['Value']), 'branch' : unicode(branch['Name']) }
        #print product



vulnerabilities = {}

for vulnerability in cvrf['Vulnerability']:
    vulnerabilities[vulnerability['CVE']] = {'title': unicode(vulnerability['Title']['Value'])}
    """if vulnerability['CVE'] == 'CVE-2018-1025':
        print vulnerability"""

    for note in vulnerability['Notes']:
        if note['Type'] == 2:
            vulnerabilities[vulnerability['CVE']]['description'] = unicode(note['Value'])
        if note['Type'] == 7:
            vulnerabilities[vulnerability['CVE']]['component'] = unicode(note['Value'])
    vulnerabilities[vulnerability['CVE']]['products'] = []
    for product in vulnerability['ProductStatuses'][0]['ProductID']:
        vulnerabilities[vulnerability['CVE']]['products'].append({'name': products[product]['name'], 'branch': products[product]['branch']})
        vulnerabilities[vulnerability['CVE']]['products'][
            len(vulnerabilities[vulnerability['CVE']]['products']) - 1]['vector'] = 'n/a'
        vulnerabilities[vulnerability['CVE']]['products'][
            len(vulnerabilities[vulnerability['CVE']]['products']) - 1]['base_score'] = 'n/a'

        for cvss in vulnerability['CVSSScoreSets']:

            if cvss['ProductID'][0] == product:
                vulnerabilities[vulnerability['CVE']]['products'][
                    len(vulnerabilities[vulnerability['CVE']]['products']) - 1]['vector'] = cvss['Vector']
                vulnerabilities[vulnerability['CVE']]['products'][
                    len(vulnerabilities[vulnerability['CVE']]['products']) - 1]['base_score'] = cvss['BaseScore']



                """break
            else:
                vulnerabilities[vulnerability['CVE']]['products'][
                    len(vulnerabilities[vulnerability['CVE']]['products']) - 1]['vector'] = 'n/a'
                vulnerabilities[vulnerability['CVE']]['products'][
                    len(vulnerabilities[vulnerability['CVE']]['products']) - 1]['base_score'] = 'n/a'"""
        #print vulnerability['CVE']
        #print vulnerabilities[vulnerability['CVE']]
    for control in vulnerability['Remediations']:
        if control['Type']==2:
            print vulnerability['CVE'] + ' : ' + control['Description']['Value'] + ' : ' + control['SubType']

#print vulnerabilities['CVE-2018-1025']

output_data = []

for id, vulnerability in vulnerabilities.items():

    for product in vulnerability['products']:
        output_data.append({'branch' : product['branch'].encode("utf8"), 'name' : product['name'].encode("utf8"), 'base_score' : product['base_score'],
                            'CVE' : id.encode("utf8"), 'title' : vulnerability['title'].encode("utf8"), 'vector' : product['vector'].encode("utf8"),
                            'description' : vulnerability['description'].encode("utf8"), 'component' : vulnerability['component'].encode("utf8")})

with open('C:/temp/cve_jul2018.csv', "w") as out_file:
        writer = csv.DictWriter(out_file, delimiter=';', fieldnames=output_data[0].keys(), lineterminator='\n')
        writer.writeheader()
        for row in output_data:
            writer.writerow(row)
print '------------------------\n'
vulns_kb = []
for vulnerability in cvrf['Vulnerability']:
    for remediation in vulnerability['Remediations']:
        if ('ProductID' in remediation.keys()):

            for product in remediation['ProductID']:
                vulns_kb.append({'CVE': vulnerability['CVE'].encode("utf8"),
                             'KB': remediation['Description']['Value'].encode("utf8"),
                             'Type': remediation['SubType'].encode("utf8"),
                             'Product': products[product]['name'].encode("utf8")})

with open('C:/temp/cvekb_jul2018.csv', "w") as out_file:
        writer = csv.DictWriter(out_file, delimiter=';', fieldnames=vulns_kb[0].keys(), lineterminator='\n')
        writer.writeheader()
        for row in vulns_kb:
            writer.writerow(row)