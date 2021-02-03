
import pandas as pd
import  numpy as np


import pandas as pd

pd.set_option('display.width', 400)
pd.set_option('display.max_columns', 30)
pd.set_option('display.max_rows', 2000)
#PARTIE UN PEU MOISIE
'''
a = pd.read_csv('message.txt',delimiter="\s+", index_col=False)
a.head()
cols = []
a.drop(a.columns[cols], axis=1,inplace=True)
print(a.iloc[2])
a.head(25)
'''
def time_interval(time1,time2):
  t1 = sum(x * int(t) for x, t in zip([3600, 60, 1], time1.split(":")))
  t2 = sum(x * int(t) for x, t in zip([3600, 60, 1], time2.split(":")))
  return abs(t1-t2)


#Partie sur le .log copié
headerString = 'date time time-taken c-ip cs-username cs-auth-group x-exception-id sc-filter-result cs-categories cs(Referer) sc-status s-action cs-method rs(Content-Type) cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-uri-extension cs(User-Agent) s-ip sc-bytes cs-bytes x-virus-id'
header = headerString.split(" ")
a = pd.read_csv('./Data/bigTest.txt', delimiter="\s+", index_col=False, encoding="utf-8", skiprows=[0, 1, 2, 3, 4, 5], names=header)
a.insert(len(a.columns),"url_size", a["cs(Referer)"])
a["url_size"] = a["url_size"].apply(lambda x: len(str(x)))
a = a.sort_values(by=['url_size'],ascending=False)
print(a.head(20))

cs_host_frequency = a.groupby(['cs-host']).count().sort_values(by=["url_size"],ascending=False)
most_frequent = cs_host_frequency.index.tolist()
quantity = cs_host_frequency["date"].tolist()
frequent_host_dict = dict(zip(most_frequent, quantity))

a.insert(len(a.columns),"cs-host-frequency", a["cs-host"])
a["cs-host-frequency"] = a["cs-host-frequency"].apply(lambda x: frequent_host_dict.get(x))
print(a["cs-host-frequency"].head())
#The max amount of log from the same user to get a better understanding
#print(a["c-ip"].mode())
b = a.sort_values(by=['c-ip', 'cs(Referer)'])
#print(b.head(200))

c = b[b["c-ip"]=="195e047d75339fd1"]
#print(c.head(2000))
'''
lasttime = "14:45:02"
lasturl = ""
streak = 0
for index, row in b.iterrows():
    if lasturl == row["cs(Referer)"]:
        if time_interval(lasttime,row["time"])>=3:
            streak+=1
            if streak>= 5:
                print(lasturl)
    else:
        streak = 0
        lasturl = row["cs(Referer)"]
    lasttime = row["time"]
#the x-exception-id
#print(a['x-exception-id'].unique())
'''

'''
['-' 'internal_error' 'invalid_request' 'policy_denied' 'tcp_error'
 'unsupported_protocol' 'dns_unresolved_hostname' 'dns_server_failure'
 'invalid_response' nan 'cs-auth-group']
'''

#the different sc-status
#print(a['sc-status'].unique())

'''
[302 200 304 301 404 403 400 0 206 503 500 204 509 410 406 401 307 303 100
 408 501 508 504 502 405 411 300 201 '200' '400' '403' '206' '304' '0'
 '404' '302' '204' '301' '500' '401' '503' '406' '100' nan 'cs(Referer)']

Information sur le sc status:
https://docs.microsoft.com/fr-fr/troubleshoot/iis/http-status-code
1 xx - Informations
2 xx - Réussite
3 xx - Redirection
4 xx - Erreur du client
-400 - Demande non bonne
-401 - Accès refusé.
-403 - Interdit.
-404 - In trouvé.
5 xx - Erreur de serveur
'''

#the different s-actions
#print(a["s-action"].unique())

"""
['TCP_NC_MISS' 'TCP_HIT' 'TCP_MISS' 'TCP_ERR_MISS' 'TCP_REFRESH_MISS'
 'TCP_DENIED' 'TCP_TUNNELED' 'TCP_PARTIAL_MISS' 'TCP_CLIENT_REFRESH'
 'TCP_NC_MISS_RST' '-' 'TCP_MISS_RST' 'TCP_AUTH_HIT' 'TCP_AUTH_MISS' nan
 'sc-status']
"""

#print(a['cs-method'].unique())
