import json
import re
import matplotlib.pyplot as plt
import yake
# main_dict = {}

# new_dict = {'A':1}
# for key in new_dict:
#     if key not in main_dict:
#         main_dict[key] = new_dict[key]
#     else:
#         # update warning instances, which is list of dicts
#         main_dict[key].extend(new_dict[key])

a = None
print('asdf' + str(a))
exit()


all_warnings = {'service':{'a':[{'warning':'asdf','b':'asdf','c':'asdf'}, {'warning':'asdf','e':'asdf','f':'asdf'}]}, 'service2':{'a':[{'warning':'asdf','b':'asdf','c':'asdf'}, {'warning':'asdf','e':'asdf','f':'asdf'}]}}

kw_extractor = yake.KeywordExtractor()
kw_extractor.stopword_set = ['warning','explanation','recommendation']
text = str(all_warnings).lower()

language = "en"
max_ngram_size = 3
deduplication_threshold = 0.9
numOfKeywords = 20
custom_kw_extractor = yake.KeywordExtractor(lan=language, n=max_ngram_size, dedupLim=deduplication_threshold, top=numOfKeywords, features=None)

text = re.findall('warning...\'.*\'', text)
print(text)
keywords = custom_kw_extractor.extract_keywords(str(text))
#text = re.sub(',.*:', '', str(dict))

print(keywords)



exit()
a = [('unused security groups', 2.321183743196205e-07),
('unused virtual private', 8.324707034485042e-07),
('security group outbound', 8.400187697357548e-07),
('remove unused security', 1.1849820141653322e-06),
('security groups efficiently', 1.330017619363781e-06),
('security groups increase', 1.3398496051119057e-06),
('managing security groups', 1.3398496051119057e-06),
('virtual private gateway', 2.3885664539904166e-06),
('potential security risk', 2.7223359248660074e-06),
('security group', 3.136099751175521e-06),
('group outbound rules', 3.3086473623451736e-06),
('allowing outbound traffic', 3.5634372242701997e-06),
('restrict egress traffic', 4.404102894302359e-06),
('private gateways cloud', 5.884938523811266e-06),
('gateways cloud lead', 7.112236775325453e-06),
('unused security', 7.303434013002475e-06),
('leave resources vulnerable', 1.0293836076983455e-05),
('tagging resources makes', 1.1142911957333582e-05),
('elastic compute cloud', 1.3410765111567325e-05),
('aws cli', 1.619005615195803e-05)]

x = []
y = []

max_label_len = 0
fontsize = 6

for item in a:
    y.append(item[0])#'\n'.join(item[0].split()))
    max_label_len = max(max_label_len, len(item[0]))
    x.append(item[1])

# totalweight = sum(y)
# for i in range(len(y)):
#     y[i] /= totalweight

title = 'Proportion of Occurences Per Keyword'

fig, ax = plt.subplots()
#ax.bar(x=x, height=y)
ax.barh(y=y, width=x)
#fig.tight_layout(h_pad=-2)

fig.subplots_adjust(left=min(0.7, max_label_len*fontsize/800), right=0.9)
#ax.xaxis.tick_top()

# for c in ax.containers:
#     ax.bar_label(c, labels=x, label_type='edge', fontsize=6, rotation=90)
# ticks = []
# numOfKeywords = 20
# for i in range(numOfKeywords):
#     ticks.append(i*10)

plt.yticks(fontsize=fontsize)
plt.ylabel('Keyword') 
plt.xlabel('Proportion of Occurences') 
plt.title(title)
#fig.autofmt_xdate() # after plotting  
plt.savefig('_'.join(title.lower().split())+'.png') 
plt.show() 
