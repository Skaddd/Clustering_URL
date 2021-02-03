
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


#### Partie sur le .log copié ####
#### IMPORT dataset ####
headerString = 'date time time-taken c-ip cs-username cs-auth-group x-exception-id sc-filter-result cs-categories cs(Referer) sc-status s-action cs-method rs(Content-Type) cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-uri-extension cs(User-Agent) s-ip sc-bytes cs-bytes x-virus-id'
header = headerString.split(" ")
a = pd.read_csv('./Data/bigTest.txt', delimiter="\s+", index_col=False, encoding="utf-8", skiprows=[0, 1, 2, 3, 4, 5], names=header)

#### Adding statistics columns ####
def add_url_size(df):
  df["url_size"] = df["cs(Referer)"].apply(lambda x: len(str(x)))
  return df

def urlsize_superior_than(df, size):
  df["url_size"] = df["cs(Referer)"].apply(lambda x: len(str(x))>=size)
  return df

def is_big_cs_bytes(df,size):
  df["bigcs"] = df["cs-bytes"].apply(lambda x: int(x)>=size)
  return df

def preprocessing(df):
  df.replace("-", "",inplace = True)
  df = df[pd.to_numeric(df['cs-bytes'], errors='coerce').notnull()]
  df = df[pd.to_numeric(df['sc-bytes'], errors='coerce').notnull()]

  return df
a = preprocessing(a)
a = urlsize_superior_than(a,10)
a = is_big_cs_bytes(a,10000)
print(a.head(200))

def amount_people_by(df, columnname):
  columnname_by = str("people-by")+str(columnname)
  df[columnname_by] =  df.groupby([columnname]).nunique()

def add_amount_people_by(df, columnname):
  columnname_by = str("people_by")+str(columnname)
  df = df.drop_duplicates(subset=[columnname,"c-ip"])
  df_frequency = df.groupby([columnname]).count()
  most_frequent = df_frequency.index.tolist()
  quantity = df_frequency.iloc[:,0].tolist()

  frequent_host_dict = dict(zip(most_frequent, quantity))

  df[columnname_by] = df[columnname].apply(lambda x: frequent_host_dict.get(x))
  #print(df.head())
  return df

a = add_amount_people_by(a,"cs-host")
print(a.head)

def add_frequency(df, columnname):
  columnnamefreq = str(columnname)+str("-frequency")
  df_frequency = df.groupby([columnname]).count()
  most_frequent = df_frequency.index.tolist()
  quantity = df_frequency.iloc[:,0].tolist()
  frequent_host_dict = dict(zip(most_frequent, quantity))

  df[columnnamefreq] = df[columnname].apply(lambda x: frequent_host_dict.get(x))
  #print(df.head())
  return df

def make_dummies(df, string):
  df = pd.concat([df, pd.get_dummies(df[string], prefix=string)], axis=1)
  df.drop([string], axis=1, inplace=True)
  return df

def compute_similarity(string1, stand_val):
  indexes = np.where(string1 == stand_val)
  return indexes[0]

def apply_sim(data, column_name, one_line_df, new_col_name):
  if column_name not in data.columns:
    print("Wrong column name")
    return 0
  else:
    list_indexes = compute_similarity(data[column_name].values, one_line_df[column_name].values[0])
    data[new_col_name] = data.index.isin(list_indexes)
    data[new_col_name] = data[new_col_name].astype(int)
  return data

def compute_all_sims(data, y):
  all_cols = ['x-exception-id', 'cs-categories',
              'sc-status', 's-action', 'cs-uri-scheme', 'cs-uri-port']
  for col in all_cols:
    apply_sim(data, col, y, 'sim')
    if 'final_sim' not in data.columns:
      data['final_sim'] = data['sim']
    else:
      data['final_sim'] = data['final_sim'] + data['sim']


### adding the columns ###
'''
y=a.tail(1)
a=make_dummies(a,'sc-filter-result')
a = add_url_size(a)
a = add_frequency(a,'cs-host')
compute_all_sims(a,y)
'''

def normalization_zero_one(df, list_column):
  for column in list_column:
    df[column] = (df[column] - df[column].min()) / (df[column].max() - df[column].min())
  return df

def normalization_gauss(df, list_column):
  for column in list_column:
    df[column] = (df[column] - df[column].mean()) / df[column].std()
  return df

### Normalizing ###
'''
only_values = a[['cs-bytes','sc-bytes','url_size','cs-host-frequency','sc-filter-result_DENIED','sc-filter-result_OBSERVED','sc-filter-result_PROXIED']]

#only_values = only_values.dropna()
#only_values = only_values.loc[only_values['cs-bytes'] == '-', 'cs-bytes'] = ""
#only_values = only_values.loc[only_values['sc-bytes'] == '-', 'sc-bytes'] = ""


#only_values[pd.to_numeric(only_values['cs_bytes'], errors='coerce').notnull()]
#only_values[pd.to_numeric(only_values['sc_bytes'], errors='coerce').notnull()]
#only_values['cs-bytes'] = pd.to_numeric(only_values['cs-bytes'],errors='coerce').notnull()
#only_values['sc-bytes'] = pd.to_numeric(only_values['sc-bytes'],errors='coerce').notnull()
only_values = only_values[pd.to_numeric(only_values['cs-bytes'], errors='coerce').notnull()]
only_values = only_values[pd.to_numeric(only_values['sc-bytes'], errors='coerce').notnull()]
only_values = only_values.astype(float)

normalization_zero_one(only_values,['cs-bytes','sc-bytes','url_size','cs-host-frequency'])
print(only_values.head())

'''

####Getting the log that are sent periodically
'''
def time_interval(time1,time2):
  t1 = sum(x * int(t) for x, t in zip([3600, 60, 1], time1.split(":")))
  t2 = sum(x * int(t) for x, t in zip([3600, 60, 1], time2.split(":")))
  return abs(t1-t2)

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
#### Some random stats to get to know the dataset ####

#The max amount of log from the same user to get a better understanding
#print(a["c-ip"].mode())
#b = a.sort_values(by=['c-ip', 'cs(Referer)'])
#print(b.head(200))

#c = b[b["c-ip"]=="195e047d75339fd1"]
#print(c.head(2000))


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
