import boto3
import botocore
import matplotlib.pyplot as plt 
import yake

import json

from service_analyzers import iam
from service_analyzers import ec2
from service_analyzers import s3
from service_analyzers import cloudtrail

all_warnings = {}

# Some services interact with other services.
# We may want to break down one service's error into sub-errors based on the other services they interact with, 
# but without affecting the total count of all_warnings. So we use this dict.
sub_warnings = {}

# open session with the account
with open('Credentials.json', 'r') as credsFile:
    credsData = json.load(credsFile)

    if (not credsData['AWS']['access_key_id'] or not credsData['AWS']['secret_access_key']):
        credsData['AWS']['access_key_id'] = input("Please enter Access Key ID:")
        credsData['AWS']['secret_access_key'] = input("Please enter Secret Access Key:")

        with open('Credentials.json', 'w') as credsFileOut:    
            json.dump(credsData, credsFileOut, indent=4)

accessKeyId = credsData['AWS']['access_key_id']
secretAccessKey = credsData['AWS']['secret_access_key']

session = boto3.Session(aws_access_key_id=accessKeyId, aws_secret_access_key=secretAccessKey)

print('Populating service clients...')
clients = {}

options = input(
'''Please type the names of the services you wish to check separated by spaces
"all" to check all services,
"s3" for S3,
"ct" for Cloudtrail,
"iam" for IAM,
"ec2" for EC2

For example, if you wish to check IAM and EC2, type "iam ec2"\n''')

options = options.lower().split()
show_graphs = False

###-------------------------------------------------- S3 SECTION ----------------------------------------------------------------------

if ('all' in options or 's3' in options):
    print('Acquiring s3 client...')
    s3_checker = s3.S3SecurityChecker(session)
    clients['s3'] = s3_checker.s3_client

# ###------------------------------------------------ CLOUDTRAIL SECTION ----------------------------------------------------------------------

if ('all' in options or 'ct' in options):
    print('Acquiring cloudtrail client')
    clients['cloudtrail'] = ''

###---------------------------------------------------IAM SECTION----------------------------------------------------------------------
if ('all' in options or 'iam' in options):
    print('Acquiring iam client...')
    clients['iam'] = session.client('iam')

###---------------------------------------------------EC2 SECTION----------------------------------------------------------------------
#1.since an account can have multiple instances in different regions, get a list of regions where the service is available
if ('all' in options or 'ec2' in options):
    print('Acquiring ec2 available regions...')
    ec2_regions = []
    for regionName in session.get_available_regions('ec2'):
        try:
            print('Getting region...')
            ec2_clientTMP = session.client('ec2', region_name=regionName)
            ec2_clientTMP.describe_instances()
            ec2_regions.append(regionName)
        except botocore.exceptions.ClientError as e:
            print(f"region unavailable: {regionName}: {str(e)}")
            pass

    #2.create a list of service "client" objects for each region for the service and obtain a description of those EC2 instances

    print('Creating list of ec2 clients...')
    ec2_clients_List = []

    for i in range(len(ec2_regions)):
        ec2_clients_List.append(session.client('ec2', ec2_regions[i]))

    clients['ec2'] = ec2_clients_List

###-------------------------------------------------- PERFORM CHECKS -----------------------------------------------------------

# We ended up performing checks and saving warnings in various different ways, so it is a bit disorganized
# iam and ec2 pass the client to run checks, then saves warnings in a var in their modules
# s3 uses a class to makes its own client and run checks. It returns warnings directly; it does not save in a var
# cloudtrail runs a starting function, which creates a client and runs checks. It saves warnings in a var

# all_warnings contains services, which contain warning_categories, which contain warning_instances:
# all_warnings (dict)
#  |
#  services (dict)
#   |
#   warning_categories (dict)
#    |
#    warning instances (list of dicts)

def w_update(main_dict, new_dict):
    '''
    Cross-warnings may be generated from the module for any related service
    e.g. iam-ec2 warnings generated in iam, or in ec2 modules.

    This function can be used to combine those cross-warnings into one service-set 
    dict, but only if the service-set is named the same way. AND, if all warning 
    categories under each service-set dict are DIFFERENT.

    So in general, try to use alphabetical ordering for the service-set names, 
    and try not to do redundant warning checks in different modules.

    For now, this function is unused
    '''
    for key in new_dict:
        if key not in main_dict:
            main_dict[key] = new_dict
        else:
            # ASSUMES WARNING CATEGORIES ARE ALL DIFFERENT
            main_dict[key].extend(new_dict)


for service, client in clients.items():
    service = service.lower()

    if service == 'iam':
        print('Performing IAM checks...')
        iam.check_IAM_EC2_configurations(clients['ec2'])
        iam.analyze_local_managed_policies(clients['iam'])

        all_warnings['iam'] = iam.get_all_warnings()
        sub_warnings['iam-only'] = iam.get_iam_only_warnings()
        sub_warnings['iam-ec2'] = iam.get_iam_ec2_warnings()
        sub_warnings['iam-ec2-vpc'] = iam.get_iam_ec2_vpc_warnings()
    
    if service == 'ec2':
        print('Performing EC2 checks...')
        # note this client is actually a list of clients, as opposed to a single client
        # we also need to recreate clients on the fly, so we pass session since it has credentials necessary to make them
        ec2.check_EC2_configurations(clients['ec2'], session)

        all_warnings['ec2'] = ec2.get_all_warnings()
        sub_warnings['ec2-only'] = ec2.get_ec2_only_warnings()
        sub_warnings['ec2-ebs'] = ec2.get_ec2_ebs_warnings()
        sub_warnings['ec2-vpc'] = ec2.get_ec2_vpc_warnings()

    if service == 's3':
        print('Performing S3 checks...')
        all_warnings['s3'] = s3_checker.get_all_warnings()
        sub_warnings['s3-only'] = all_warnings['s3']
    
    if service == 'cloudtrail':
        print('Performing CloudTrail checks...')
        cloudtrail.starting_function()
        all_warnings['cloudtrail'] = cloudtrail.get_all_warnings()
        sub_warnings['cloudtrail-only'] = all_warnings['cloudtrail']

################################### GRAPH SECTION ########################################

#print(all_warnings)
print("Creating graphs...")
### UNIQUE WARNINGS PER SERVICE ###
x = []
y = []

# In case warnings are returned in an erroneous way, we'll simply ignore them
# However, we still keep them around because they can be used for NLP

### DEFINING SOME FUNCTIONS ###
def isolate_warning_text(label:str, all_dict:dict):
    text = ''
    for service, wc_dict in all_dict.items():
        for _, instances in wc_dict.items():
            for inst_dict in instances:
                try:
                    if label in inst_dict:
                        text += inst_dict[label] + ' '
                    if label.lower() in inst_dict:
                        text += inst_dict[label.lower()] + ' '
                    if label.capitalize() in inst_dict:
                        text += inst_dict[label.capitalize()] + ' '
                    if label.upper() in inst_dict:
                        text += inst_dict[label.upper()] + ' '
                except:
                    print(f'Error with label {label} or dict {inst_dict}')
            continue
    return text.lower()

def get_keyword_info(keywords):
    max_len = 0
    x = []
    y = []
    for kw in keywords:
        max_len = max(max_len, len(kw[0]))
        y.append(kw[0])
        x.append(kw[1])
    return x, y, max_len

def create_hbar(y, x, ylabel, xlabel, max_label_len, fontsize):
    fig, ax = plt.subplots()
    ax.barh(y=y, width=x)
    fig.subplots_adjust(left=min(0.7, max_label_len*fontsize/600), right=0.9)

    #title = 'Proportion of Occurences Per Keyword'
    title = xlabel + ' Per ' + ylabel
    plt.yticks(fontsize=fontsize)
    plt.ylabel(ylabel) 
    plt.xlabel(xlabel) 
    plt.title(title)
    plt.savefig('logs/'+'_'.join(title.lower().split())+'.png')
    if show_graphs:
        plt.show()
    return True 

# def do_nlp_on(label_name, all_text):
#     '''Does NLP on everything by default'''

#     if label_name != None:
#         text = isolate_warning_text(label_name, all_text)
#     keywords = custom_kw_extractor.extract_keywords(text)
#     x, y, max_len = get_keyword_info(keywords)
#     create_hbar(y, x, 'Keyword in' + str(label_name), 'Proportion of Occurrences', max_len, fontsize=6)

### END OF DEFINING FUNCTIONS ###

### INSTANTIATING KEYWORD EXTRACTOR ###

kw_extractor = yake.KeywordExtractor()
kw_extractor.stopword_set = ['warning','explanation','recommendation']

language = "en"
max_ngram_size = 3
deduplication_threshold = 0.9
numOfKeywords = 20
custom_kw_extractor = yake.KeywordExtractor(lan=language, n=max_ngram_size, dedupLim=deduplication_threshold, top=numOfKeywords, features=None)
### END OF INSTANTIATION ###


### PROPORTION OF OCCURENCE PER KEYWORD ##
### KEYWORDS IN EVERYTHING ###
all_text = str(all_warnings).lower()
keywords = custom_kw_extractor.extract_keywords(all_text)
x, y, max_len = get_keyword_info(keywords)
create_hbar(y, x, 'Keyword', 'Proportion of Occurrences', max_len, fontsize=6)

### KEYWORDS IN WARNINGS ###
text = isolate_warning_text('Warning', all_warnings)
keywords = custom_kw_extractor.extract_keywords(text)
x, y, max_len = get_keyword_info(keywords)
create_hbar(y, x, 'Keyword in Warning', 'Proportion of Occurrences', max_len, fontsize=6)

### KEYWORDS IN EXPLANATION ###
text = isolate_warning_text('Explanation', all_warnings)
keywords = custom_kw_extractor.extract_keywords(text)
x, y, max_len = get_keyword_info(keywords)
create_hbar(y, x, 'Keyword in Explanation', 'Proportion of Occurrences', max_len, fontsize=6)

### KEYWORDS IN RECOMMENDATIONS ###
text = isolate_warning_text('Recommendation', all_warnings)
keywords = custom_kw_extractor.extract_keywords(text)
x, y, max_len = get_keyword_info(keywords)
create_hbar(y, x, 'Keyword in Recommendation', 'Proportion of Occurrences', max_len, fontsize=6)

### WARNING TYPES PER SERVICE ###
x = []
y = []

for service, wc_dict in all_warnings.items():
    try:
        x.append(service)
        y.append(len(wc_dict))
    except:
        continue

fig, ax = plt.subplots()
ax.bar(x=x, height=y)

plt.xlabel('Services') 
plt.ylabel('Number of Warning Types') 
plt.title('Number of Warning Types Per Service') 
plt.savefig('logs/number_of_warning_types_per_service.png')
if show_graphs:
    plt.show() 
# btw, u have to savefig before show. after show is called, a new (blank) figure is created 

### TOTAL WARNINGS PER SERVICE ###
x = []
y = []

for service, wc_dict in all_warnings.items():
    try:
        w_cnt = 0
        for _, w_list in wc_dict.items():
            w_cnt += len(w_list)
        x.append(service)
        y.append(w_cnt)
    except:
        continue

fig, ax = plt.subplots()
ax.bar(x=x, height=y)

plt.xlabel('Services') 
plt.ylabel("Number of Warning Instances") 
plt.title('Number of Warning Instances Per Service') 
plt.savefig('logs/total_warnings_per_service.png')
if show_graphs:
    plt.show() 

### TOTAL WARNINGS PER SERVICE SET ###
x = []
y = []
max_len = 0

for service_set, wc_dict in sub_warnings.items():
    try:
        w_cnt = 0
        for _, w_list in wc_dict.items():
            w_cnt += len(w_list)
        if len(service_set) > max_len:
            max_len = len(service_set)
        y.append(service_set)
        x.append(w_cnt)
    except:
        continue

create_hbar(y, x, 'Service Sets', 'Number of Warning Instances', max_len, 6)

#print(json.dumps(all_warnings, indent=4))
