
import pandas as pd
import  numpy as np


import pandas as pd
#PARTIE UN PEU MOISIE
'''
a = pd.read_csv('message.txt',delimiter="\s+", index_col=False)
a.head()
cols = []
a.drop(a.columns[cols], axis=1,inplace=True)
print(a.iloc[2])
a.head(25)
'''
#Partie sur le .log copié
headerString = 'date time time-taken c-ip cs-username cs-auth-group x-exception-id sc-filter-result cs-categories cs(Referer) sc-status s-action cs-method rs(Content-Type) cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-uri-extension cs(User-Agent) s-ip sc-bytes cs-bytes x-virus-id'
header = headerString.split(" ")
print(header)
a = pd.read_csv('./Data/test.txt', delimiter="\s+", index_col=False, encoding="utf-8", skiprows=[0, 1, 2, 3, 4, 5], names=header)
print(a.head())
print(a.groupby(a["c-ip"]).count().max())
'''
cols = []
#champ 8 => url donc il faut parser pour recup :
#
a.drop(a.columns[cols], axis=1,inplace=True)
print(a.iloc[2])
a.head()
'''