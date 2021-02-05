#### Libraries ####
import pandas as pd
import numpy as np
import datetime
from urllib.parse import urlparse
import httpagentparser

pd.set_option('display.width', 40000)
pd.set_option('display.max_columns', 40)
pd.set_option('display.max_rows', 2000)

#### Partie sur le .log copié ####
#### IMPORT dataset ####
headerString = 'date time time-taken c-ip cs-username cs-auth-group x-exception-id sc-filter-result cs-categories cs(Referer) sc-status s-action cs-method rs(Content-Type) cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-uri-extension cs(User-Agent) s-ip sc-bytes cs-bytes x-virus-id'
header = headerString.split(" ")
data = pd.read_csv('./Data/bigTest.txt', delimiter="\s+", index_col=False, encoding="utf-8", comment= "#", names=header)
data=data.drop(columns=['cs-username','cs-auth-group','date','time-taken','x-virus-id'])
data = data.sample(frac=0.1)

#### Preprocessing tools and removal of useless logs ####

def preprocessing(df):
  df.replace("-", "", inplace=True)
  df = df[pd.to_numeric(df['cs-bytes'], errors='coerce').notnull()]
  df = df[pd.to_numeric(df['sc-bytes'], errors='coerce').notnull()]
  return df


def remove_rows(data):
  data = data.loc[(data['x-exception-id'] == "")]
  data.loc[data['cs-host'] == "", 'empty'] = 1
  data['empty'] = data['empty'].fillna(0)
  col_name_skip = ['referer-protocol', 'referer-domain', "referer-path", "cs-host"]

  for col in data.columns:
    if col in col_name_skip:
      pass
    elif col == 'cs-uri-path':
      data.loc[data[col] == "/", "empty"] += 1

    else:
      data.loc[data[col] == "", "empty"] += 1
  data = data.loc[data['empty'] < 6]
  data = data.drop(columns=['empty', 'x-exception-id'])
  return data

data = preprocessing(data)
data = remove_rows(data)

#### Adding statistics columns ####
### FONCTIONS ###

#Fonction qui regarde si le status fait référence à une erreur
def strange_status(a):
  #a['sc-status'] = a['sc-status'].astype(float)
  a['sc-status'] = pd.to_numeric(a['sc-status'],errors='coerce')
  a['strange_status'] = np.where(a['sc-status'] < 399, 0, 1)
  return a

#Fonction qui regarde si le port est compris dans la liste des ports fréquents
def strange_port(data, tab_port, tab_method):
  data['strange_port'] = np.where(data['cs-uri-port'].isin(tab_port), 0, 1)
  data.loc[(data['cs-method'].isin(tab_method)) & (data['strange_port'] == 1), 'strange_port'] += 1

  return data


def parse_url(data, column_toparse, scheme=True, domain=True, path=True, params=False, query=False, fragment=False):
  if column_toparse not in data.columns:
    print("Column name not found")
    return 0
  else:
    try:
      data['referer-protocol'], data['referer-domain'], data['referer-path'], data['referer-params'], data[
        'referer-query'], data['referer-fragment'] = zip(*data[column_toparse].map(urlparse))
      choices = [scheme, domain, path, params, query, fragment]
      names = ['referer-protocol', 'referer-domain', 'referer-path', 'referer-params', 'referer-query',
               'referer-fragment']
      indexes = np.where(choices)[0]
      keep = []
      for k in indexes:
        keep.append(names[k])
      dropped = list(set(names) - set(keep))
      data = data.drop(columns=dropped)
    except:
      pass
  return data

def find_same_referer(data):
  data.loc[data['cs-host'] != data['referer-domain'], 'changed'] = 1
  data['changed'] = data['changed'].fillna(0)
  return data

def compute_url_size(df, poids):
  sum_column = df["cs-host"].apply(lambda x: len(str(x))) + df["cs-uri-path"].apply(lambda x: len(str(x)))
  df['url_size'] = sum_column
  threshold1 = df["url_size"].quantile(0.9)
  threshold2 = df["url_size"].quantile(0.99)
  df["url_size"] = df["url_size"].apply(
    lambda x: max(0, min(poids, poids * ((x - threshold1) / (threshold2 - threshold1)))))
  return df

def is_big_cs_bytes(df, quantile1 = 0.95,quantile2 = 0.99,poids = 2):
  df["bigcs"] = df["cs-bytes"].apply(lambda x: int(x))
  value1 = df["bigcs"].quantile(quantile1)
  value2 = df["bigcs"].quantile(quantile2)
  df["bigcs"] = df["bigcs"].apply(lambda x: max(0,min(poids,poids*((x-value1)/(value2-value1)))))
  return df

def extension_superior_than(df, size, quantile, tab_extension):
  value = df["cs-uri-extension-frequency"].quantile(quantile)

  df["extension_strange"] = np.where(df["cs-uri-extension-frequency"] > value, 0, 1)
  df['len-extension']=df['cs-uri-extension'].apply(lambda x  : len(str(x)))
  df.loc[df['len-extension']>size,"extension_strange"]=1
  df.loc[df['cs-uri-extension'].isin(tab_extension),"extension_strange"]=0.5
  df["extension_strange"] = df["extension_strange"]*2
  return df

def amount_people_by(df, columnname):
  columnname_by = str("people-by")+str(columnname)
  df[columnname_by] =  df.groupby([columnname]).nunique()

def add_amount_people_by(df, columnname, quantile1=0.5, quantile2 = 0.90, poids = 3):
  columnname_by = str("people_by")+str(columnname)
  df2 = df.drop_duplicates(subset=[columnname,"c-ip"])
  df_frequency = df2.groupby([columnname]).count()
  most_frequent = df_frequency.index.tolist()
  quantity = df_frequency.iloc[:,0].tolist()

  frequent_host_dict = dict(zip(most_frequent, quantity))

  df[columnname_by] = df[columnname].apply(lambda x: frequent_host_dict.get(x))
  value1 = df[columnname_by].quantile(quantile1)
  value2 = df[columnname_by].quantile(quantile2)
  print(value1)
  print(value2)
  df[columnname_by] = df[columnname_by].apply(lambda x: - max(0,min(poids,poids*((x-value1)/(value2-value1)))))

  #print(df.head())
  return df

def add_frequency(df, columnname):
  columnnamefreq = str(columnname)+str("-frequency")
  df_frequency = df.groupby([columnname]).count()
  most_frequent = df_frequency.index.tolist()
  quantity = df_frequency.iloc[:,0].tolist()
  frequent_host_dict = dict(zip(most_frequent, quantity))

  df[columnnamefreq] = df[columnname].apply(lambda x: frequent_host_dict.get(x))
  #print(df.head())
  return df

def compute_useragent(data, poids):
  data['more_info'] = data['cs(User-Agent)'].apply(lambda x: httpagentparser.simple_detect(x))
  data['fishy_os'] = data['more_info'].apply(lambda x: x.__contains__('Unknown OS'))
  data['fishy_browser'] = data['more_info'].apply(lambda x: x.__contains__('Unknown Browser'))
  data['fishy_os'] = (data['fishy_os'].astype(int)) * poids
  data['fishy_browser'] = (data['fishy_browser'].astype(int)) * poids
  return data

#### APPLYING THE FUNCTIONS TO GET NEW COLOMNS ####

data = strange_status(data)

tab_method = ["GET","POST","HEAD","OPTIONS","PUT","CONNECT",""]
tab_port = [80,443,"80","443",""]
data = strange_port(data,tab_port,tab_method)

data=parse_url(data,'cs(Referer)')

data = find_same_referer(data)

data=compute_url_size(data,2)

data = is_big_cs_bytes(data)

data = add_amount_people_by(data,"cs-host")

data = add_frequency(data, "cs-uri-extension")

tab_extension = ["dll","zip","rar","bin","exe"]
data = extension_superior_than(data, 20,0.004,tab_extension)

data=compute_useragent(data,1)

score_cols = ['url_size', 'bigcs', 'strange_status', 'strange_port', 'people_bycs-host', 'changed','extension_strange', 'fishy_os', 'fishy_browser']
data["sum"] = data[score_cols].sum(axis=1)

data = data.sort_values(by=["sum"],ascending=False)

print(data.head(200))

from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import matplotlib.cm as cm

amount_clusters = 8
kmeans = KMeans(n_clusters=amount_clusters, random_state=0).fit(data[score_cols])
print(kmeans.labels_)
print(kmeans.cluster_centers_)
data["final_cluster"] = kmeans.labels_
data["final_cluster"] = data["final_cluster"].astype("category")
print(data.dtypes)



from sklearn.decomposition import PCA

pca = PCA(n_components=2).fit(data[score_cols])
datapoint = pca.transform(data[score_cols])
plt.scatter(datapoint[:, 0], datapoint[:, 1])
plt.show()
x = [datapoint[:, 0]]
y = [datapoint[:, 1]]


colors = cm.rainbow(np.linspace(0, 1, amount_clusters))
print(colors)
pca = PCA(n_components=2).fit(data[score_cols])
for i in range(amount_clusters):
  subframe = data[data['final_cluster'] == i]

  datapoint = pca.transform(subframe[score_cols])
  x = [datapoint[:, 0]]
  y = [datapoint[:, 1]]
  plt.scatter(x, y, color=colors[i], s=20)
plt.show()

# plot parallel coordinates
from pandas.plotting import parallel_coordinates
score_cols = ['url_size', 'bigcs', 'strange_status', 'strange_method', 'strange_port', 'people_bycs-host', 'changed','extension_strange','final_cluster']

pd.plotting.parallel_coordinates(data[score_cols], 'final_cluster')

plt.show()
for i in range(amount_clusters):
  subframe = data[data['final_cluster'] == i]


  pd.plotting.parallel_coordinates(

    subframe[score_cols], 'final_cluster', color=('#556270', '#4ECDC4', '#C7F464')

  )
  plt.show()

'''
score_cols = ['url_size', 'bigcs', 'strange_status', 'strange_method', 'strange_port', 'people_bycs-host']

pd.plotting.parallel_coordinates(

    data, 'final_cluster', color=('#556270', '#4ECDC4', '#C7F464')

)
'''
"""
for i in range(amount_clusters) :
  subframe = data[data['final_cluster'] == i]

  score_cols = ['url_size', 'bigcs', 'strange_status', 'strange_method', 'strange_port', 'people_bycs-host', 'changed',
                'extension_strange', 'sum']

  parallel_coordinates(subframe[score_cols], 'sum')
"""
"""
import matplotlib.pyplot as plt
import seaborn as sns
f, ax = plt.subplots(figsize=(10, 6))
corr = data[score_cols].corr()
hm = sns.heatmap(round(corr,2), annot=True, ax=ax, cmap="coolwarm",fmt='.2f',
                 linewidths=.05)
f.subplots_adjust(top=0.93)
t= f.suptitle('Attributes Correlation Heatmap', fontsize=14)
#plt.show()

# Scaling attribute values to avoid few outiers


from sklearn.preprocessing import StandardScaler
ss = StandardScaler()

score_cols = ['url_size', 'bigcs', 'strange_status', 'strange_method', 'strange_port', 'people_bycs-host', 'changed','extension_strange','sum']


# plot parallel coordinates
from pandas.plotting import parallel_coordinates
parallel_coordinates(data[score_cols], 'sum')
plt.show()
"""
#### OLD PART ####
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
