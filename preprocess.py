from androguard.core.apk import APK
from androguard.core.dex import DEX
import re
from model import get_stuff,get_cols,ifmalware
import pandas as pd
#from androguard.core.bytecode.dvm import DalvikCode

path="testapks\\base.apk"
app=APK(path)
dex=DEX(app.get_dex())
permissions=app.get_permissions()
manifest=app.get_android_manifest_xml()
intent_lam=manifest.findall(".//intent-filter")
print(intent_lam[2].findall(".//action")[0].get("{http://schemas.android.com/apk/res/android}name"))
#print(manifest)

permissions_list,api_calls,intents,keywords=get_stuff()
columns=get_cols()

df=pd.DataFrame(columns=columns)
df.loc[0,"filename"]=path
#print(df.head())

'''
print(permissions_list)
print(dex.get_methods()[2].get_descriptor())
'''
app_permissions=[]
for i in permissions:
    i=i.split('.')[-1]
    if i in permissions_list:
        app_permissions.append(i)

for i in permissions_list:
    if i in app_permissions:
        df[i]=1
    else:
        df[i]=0


app_api_sings=[]
for i in dex.get_methods():
    for j in api_calls:
        if re.search(j,i.get_descriptor()):
            app_api_sings.append(j)

for i in api_calls:
    if i in app_api_sings:
        df[i]=1
    else:
        df[i]=0

#print(df.head())
app_actions=[]
for i in intent_lam:
    actions=i.findall(".//actions")
    for j in actions:
        k=j.get("{http://schemas.android.com/apk/res/android}name")
        for l in intents:
            if re.search(l,k):
                app_actions.append(l)

for i in intents:
    if i in app_actions:
        df[i]=1
    else:
        df[i]=0

app_words=[]
for i in dex.get_methods():
    for j in keywords:
        try:
            if re.search(j,i.get_code().get_instruction()):
                app_words.append(j)
        except:
            pass

for i in keywords:
    if i in app_words:
        df[i]=1
    else:
        df[i]=0
    
df=df.drop("class",axis=1)
#print(df.head()

temp=df.drop("filename",axis=1)
#df.to_csv("summa.csv")

stupid=ifmalware(temp)
print(stupid)