
import pandas as pd
import  numpy as np


import pandas as pd
#PARTIE UN PEU MOISIE
a = pd.read_csv('message.txt',delimiter="\s+", index_col=False)
a.head()
cols = []

a.drop(a.columns[cols], axis=1,inplace=True)
print(a.iloc[2])
a.head(25)

#Partie sur le .log copié
header = np.arange(1,26)
print(header)
a = pd.read_csv('./Data/test.txt', delimiter="\s+", index_col=False, encoding="utf-8", skiprows=[0, 1, 2, 3, 5],header=header)
print(a.head())
'''
cols = []
#champ 8 => url donc il faut parser pour recup :
#
a.drop(a.columns[cols], axis=1,inplace=True)
print(a.iloc[2])
a.head()
'''