import requests
import json
from pandas.io.json import json_normalize
import pandas as pd
import numpy as np



def login(baseURL,username,password):
    """
    Authenticate a user and create an HTTP session on the web server.
    
    Parameters:
    -----------
    baseURL, username, password
    
    Returns:
    --------
    authToken and sessionId.
    
    Example:
    --------
    authToken, cookies = login(baseURL, username, password)
    """
    header = {'username': username,
                'password': password,
                'loginMode': 1}
    r = requests.post(baseURL + 'auth/login', data=header)
    if r.ok:
        authToken = r.headers['X-MSTR-AuthToken']
        cookies = dict(r.cookies)
        print("Token: " + authToken)
        print("Session ID: {}".format(cookies))
        return authToken, cookies
    else:
        print("HTTP {} - {}, Message {}".format(r.status_code, r.reason, r.text))
        return []


def sessionValiade(baseURL, authToken, cookies):
    """
    Get information about a configuration session
    
    Parameters:
    ----------
    baseURL, authToken, cookies
    
    Returns:
    -------
    None
    
    Example:
    --------
    sessionValiade(baseURL, authToken, cookies)
    
    """
    print("Checking session...")
    header = {'X-MSTR-AuthToken': authToken,
                 'Accept': 'application/json'}
    r = requests.get(baseURL + "sessions", headers=header, cookies=cookies)
    
    if r.ok:
        print(r.text)
    else:
        print("HTTP {} - {}, Message {}".format(r.status_code, r.reason, r.text))
        return []


def userInfo(baseURL, authToken, cookies):
    """
    Returns:
    --------
    Pandas DataFrame
    id, fullName, initials
    
    Example:
    --------
    user = userInfo(baseURL, authToken, cookies)
    """
    header = {'X-MSTR-AuthToken': authToken,
                 'Accept': 'application/json'}
    r = requests.get(baseURL + "sessions/userInfo", headers=header, cookies=cookies)
    
    if r.ok:
        return json_normalize(json.loads(r.text))
    else:
        print("HTTP {} - {}, Message {}".format(r.status_code, r.reason, r.text))
        return []
    

def getLibrary(baseURL, authToken, cookies, flag):
    """
    Get library for authenticated user.
    
    Parameteres:
    ------------
    baseURL, authToken, cookies, flag.
    flag: 'DEFAULT' or'FILTER_TOC'
    
    Returns:
    --------
    Pandas DataFrame (pandas.core.frame.DataFrame)
    id, name, description, projectId, active, lastViewedTime
    
    Example:
    --------
    getLibrary(baseURL, authToken, cookies, 'DEFAULT')
    """
    
    header = {'X-MSTR-AuthToken': authToken,
                 'Accept': 'application/json'}
    r = requests.get(baseURL + "library?outputFlag="+ flag, headers=header, cookies=cookies)
    
    if r.ok:            
        a = pd.DataFrame(json.loads(r.text))[['id', 'name', 'projectId', 'active','lastViewedTime']]
        tmp = []
        if (flag == 'DEFAULT'):
            for i in json.loads(r.text):
                tmp.append(i['target']['id'])
            a['target'] = pd.DataFrame(tmp).astype(str)
        return a
    else:
        print("HTTP {} - {}, Message {}".format(r.status_code, r.reason, r.text))
        return []

def listProjects(baseURL, authToken, cookies):   
    """
   Get a list of projects that can be accessed by the authenticated user
    
    Parameters:
    ----------
    baseURL, authToken, cookies
    
    Returns:
    -------
    Pandas DataFrame
    Project Id, Name, Description and Status code
    
    Example:
    --------
    sessionValiade(baseURL, authToken, cookies)
    
    """
    header = {'X-MSTR-AuthToken': authToken,
                 'Accept': 'application/json'}
    r = requests.get(baseURL + 'projects', headers=header, cookies=cookies)
    if r.ok:
        return pd.DataFrame(json.loads(r.text))[['id','name','description', 'status']]
    else:
        print("HTTP {} - {}, Message {}".format(r.status_code, r.reason, r.text))
        return []



def searchObjects(baseURL, authToken, stype):
    """
    Search for meteadata Objects using EnumDSSObjectType. 
    
    Parameters:
    -----------
    baseURL, authToken, stype
    stype is based on EnumDSSObjectType values for example Folder is 8, Search is 39, Metric is 4 and Attribute is 12
    for a lsit of EnumDSSObjectType values reference https://community.microstrategy.com/s/article/KB16048-List-of-all-object-types-and-object-descriptions-in
    
    Return:
    -------
    Pandas DataFrame which contains object ID, name, type, owner and additional details
    
    Example:
    --------
    searchObjects(baseURL, authToken, '8')
    
    """
    
    header = {'X-MSTR-AuthToken': authToken,
              'X-MSTR-ProjectID': projectId,
              'Accept': 'application/json'}
    
    r = requests.get(baseURL + 'searches/results?type='+ stype, headers=header, cookies=cookies)
    
    if r.ok:
        return pd.DataFrame(json.loads(r.text)['result'])
    else:
        print("HTTP {} - {}, Message {}".format(r.status_code, r.reason, r.text))
        return []

def cubeObjects(baseURL, authToken, projectId, cookies, cubeId):
    """
    Get definition of a specific cube with cubeId 
    
    Parameters:
    -----------
    baseURL, authToken, projectId, cookies, cubeId
    
    Return:
    -------
    Pandas DataFrame which contains object ID, Object Name and Type (Attribute or Metrics)
    
    Example:
    --------
    cubeObjects(baseURL, authToken, projectId, cookies, 'BD23848347017FC2C0B4509AED1AF7B4')
    
    """
    header = {'X-MSTR-AuthToken': authToken,
                  'X-MSTR-ProjectID': projectId,
                 'Accept': 'application/json'}
    
    r = requests.get(baseURL + 'cubes/' + cubeId, headers=header, cookies=cookies)
    
    if r.ok:
        node = r.json()
        attr =  pd.DataFrame(node['result']['definition']['availableObjects']['attributes'])[['id', 'name', 'type']]
        mtrcs =  pd.DataFrame(node['result']['definition']['availableObjects']['metrics'])[['id', 'name', 'type']]
        return pd.concat([attr, mtrcs])
    else:
        print("HTTP {} - {}, Message {}".format(r.status_code, r.reason, r.text))
        return []

def logout(baseURL,authToken):
    
    header = {'X-MSTR-AuthToken': authToken,
                  'Accept': 'application/json'}

    r = requests.post(baseURL + 'auth/logout',headers=header, cookies=cookies)
    if r.ok:
        print("Logged Out")
       
    else:
        print("HTTP {} - {}, Message {}".format(r.status_code, r.reason, r.text))
