import pandas as pd

data=pd.read_csv("Dataset\\drebin-215-dataset-5560malware-9476-benign.csv",encoding="utf-8",na_values="?")

'''
temp=data.head()
print(data.isnull().sum().sum())
'''

features=pd.read_csv("Dataset\\dataset-features-categories.csv",encoding="utf-8",na_values="?",names=['service','category'])

'''
print(features.head())
print(features["category"].value_counts())
print(features.shape)
'''

data["class"]=data["class"].map({'S':0,'B':1})
data=data.dropna()

'''
print(data.head())
print(data["class"].value_counts())
'''

X=data.drop("class",axis=1)
y=data["class"]

from sklearn.model_selection import train_test_split
X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=42)

from sklearn.linear_model import LogisticRegression

log_reg=LogisticRegression()
log_reg.fit(X_train,y_train)

from sklearn.model_selection import cross_val_score

crossvalscore=cross_val_score(log_reg,X_test,y_test,cv=4)
print("crossvalscore")
print(crossvalscore)

from sklearn.metrics import confusion_matrix
from sklearn.model_selection import cross_val_predict
y_train_predicted=cross_val_predict(log_reg,X_train,y_train,cv=3)
print("confusion matrix of train")
confmatrix=confusion_matrix(y_train,y_train_predicted)
print(confmatrix)

y_test_predicted=cross_val_predict(log_reg,X=X_test,y=y_test,cv=3)
print("confusion matrix of test")
confmatrix1=confusion_matrix(y_test,y_test_predicted)
print(confmatrix1)

print(features.head())

def get_stuff():
    bump1=features[features["category"]=="Manifest Permission"].service.unique()
    bump2=features[features["category"]=="API call signature"].service.unique()
    bump3=features[features["category"]=="Intent"].service.unique()
    bump4=features[features["category"]=="Commands signature"].service.unique()
    return bump1,bump2,bump3,bump4

def get_cols():
    columns=["filename"]
    for i in data.columns:
        columns.append(i)
    return columns

def ifmalware(X):
    ans=log_reg.predict_proba(X)
    return ans