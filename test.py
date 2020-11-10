import csv
from collections import namedtuple
policyFile = 'policies.csv'
Policies = namedtuple('Policy', ['id','src', 'dst'])

with open(policyFile, mode='r') as file:
    csvFile = csv.DictReader(file)

    policies = []

    for lines in csvFile:
        #print(lines)
        dict = Policies(lines['id'],lines['mac_0'], lines['mac_1'])
        policies.append(dict)
print(policies)
