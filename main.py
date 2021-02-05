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
data = pd.read_csv('./Data/BitTest2.txt', delimiter="\s+", index_col=False, encoding="utf-8", comment= "#", names=header)
data=data.drop(columns=['cs-username','cs-auth-group','date','time-taken','x-virus-id'])
data = data.sample(frac=0.01)

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

print(len(data))
data = preprocessing(data)

print(len(data))
data = remove_rows(data)

print(len(data))
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
  data['strange_port'] = np.where(data['cs-uri-port'].isin(tab_port), 0, 8)
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

print(len(data))
tab_method = ["GET","POST","HEAD","OPTIONS","PUT","CONNECT",""]
tab_port = [80,443,"80","443",""]
data = strange_port(data,tab_port,tab_method)

print(len(data))
data=parse_url(data,'cs(Referer)')

print(len(data))
data = find_same_referer(data)

print(len(data))
data=compute_url_size(data,2)

print(len(data))
data = is_big_cs_bytes(data)

print(len(data))
data = add_amount_people_by(data,"cs-host")

print(len(data))
data = add_frequency(data, "cs-uri-extension")

print(len(data))
tab_extension = ["dll","zip","rar","bin","exe"]
data = extension_superior_than(data, 20,0.004,tab_extension)

print(len(data))
data=compute_useragent(data,1)

score_cols = ['url_size', 'bigcs', 'strange_status', 'strange_port', 'people_bycs-host', 'changed','extension_strange', 'fishy_os', 'fishy_browser']
data["sum"] = data[score_cols].sum(axis=1)

data = data.sort_values(by=["sum"],ascending=False)

print(data.head(200))


import matplotlib.pyplot as plt
import seaborn as sns
f, ax = plt.subplots(figsize=(10, 6))
corr = data[score_cols].corr()
hm = sns.heatmap(round(corr,2), annot=True, ax=ax, cmap="coolwarm",fmt='.2f',
                 linewidths=.05)
f.subplots_adjust(top=0.93)
t= f.suptitle('Attributes Correlation Heatmap', fontsize=14)
plt.show()

from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import matplotlib.cm as cm

amount_clusters = 3
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


fig, axs = plt.subplots(3, 3)

for i in range(2,12):
  amount_clusters = i
  kmeans = KMeans(n_clusters=amount_clusters, random_state=0).fit(data[score_cols])
  data["final_cluster"] = kmeans.labels_
  data["final_cluster"] = data["final_cluster"].astype("category")
  colors = cm.rainbow(np.linspace(0, 1, amount_clusters))
  for i in range(amount_clusters):
    subframe = data[data['final_cluster'] == i]

    datapoint = pca.transform(subframe[score_cols])
    x = [datapoint[:, 0]]
    y = [datapoint[:, 1]]
    axs[(i-2)//3, (i-2)%3].scatter(x, y, color=colors[i], s=20)
    cop = amount_clusters

plt.show()




# plot parallel coordinates
from pandas.plotting import parallel_coordinates

amount_clusters = 10
kmeans = KMeans(n_clusters=amount_clusters, random_state=0).fit(data[score_cols])
data["final_cluster"] = kmeans.labels_
data["final_cluster"] = data["final_cluster"].astype("category")
score_cols = ['url_size', 'bigcs', 'strange_status', 'strange_port', 'people_bycs-host', 'changed','extension_strange', 'fishy_os', 'fishy_browser','final_cluster']

pd.plotting.parallel_coordinates(data[score_cols], 'final_cluster')

plt.show()
for i in range(amount_clusters):
  subframe = data[data['final_cluster'] == i]


  pd.plotting.parallel_coordinates(

    subframe[score_cols], 'final_cluster', color=('#556270', '#4ECDC4', '#C7F464')

  )
  plt.show()


