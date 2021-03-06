# MicroStrategy Embedding - How to embed an interactive Dossier during your analysis within Jupyter Notebook

### Python, JavaScript and HTML with Jupyter magic cells

Scenario: 

To demonstrate how to use a python Jupyter Notebook to navigate and find the Dossier we are interested in, display it inside Jupyter Notebook for interactive data analysis. This will help us better understand the data as published by business and before we start loading the data from the cube(s) into DataFrames. This way we will get better insight into the type of analysis done by the business, and how they prefer to see and digest their data to help us gain a better intuition about the business use case(s) and driver.

In this example I will show you how to use pure code all within Jupyter Notebook to accomplish this without having to go to MicroStrategy Web or needing to right-click to get object properties to obtain IDs for the project or document.  

This tutorial follows the **MicroStratety REST API with Python** examples here https://github.com/tatwan/MicroStratety-Python-REST-API and my previous blog on **How to Embed MicroStrategy Dossier with Jupyter Notebook** here http://www.tarekatwan.com/index.php/2018/01/how-to-embed-microstrategy-dossier-with-jupyter-notebook/  

### We start by loading the Python libraries 


```python
import requests
import json
from pandas.io.json import json_normalize
import pandas as pd
```

### Define our parameters 
`username`. `password`, and `baseURL`


```python
### Parameters ###
username = 'Administrator'
password = ''
baseURL = "http://yourMstrEnv/MicroStrategyLibrary/api/"
```

Next we load our python functions from this tutorial https://github.com/tatwan/MicroStratety-Python-REST-API . All that was done is placing the python code/script into a `mstr.py` file then we use `import mstr`. You can name the file anything you want.


```python
import mstr 
```

### Steps:
1. First we authenticate to get `authToken` and `sessionId` using the `login()` function 
2. After we are authenticated, we will list all the projects that we have access to using our `listProjects()` function
3. Select the project you want and save the `id` of that project into variable we will name `projectId`  
4. Next we list our library using the `getLibrary()` function in order to find the `id` of the published Dossier we are interested in. In this case we need the `id` from the `target` column and we will save it into `libraryId` variable. To get the `target` columns we pass `DEFAULT` for the flag parameter. If we use `FILTER_TOC` we don't get that column.

```python
#step 1 - authenticate 

authToken, sessionId = mstr.login(baseURL, username, password)
```

    Token: 8fa2ngoiak50597n968cpo7so7
    Session ID: {'JSESSIONID': '2E05323BE41684698BF62C35AE9900BB'}
    


```python
#step 2 - search  projects

projectList = mstr.listProjects(baseURL, authToken, sessionId)
projectList
```




<div>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>id</th>
      <th>name</th>
      <th>description</th>
      <th>status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>B19DEDCC11D4E0EFC000EB9495D0F44F</td>
      <td>MicroStrategy Tutorial</td>
      <td>MicroStrategy Tutorial project and application...</td>
      <td>0</td>
    </tr>
    <tr>
      <th>1</th>
      <td>AF09B3E3458F78B4FBE4DEB68528BF7B</td>
      <td>Human Resources Analysis Module</td>
      <td>The Human Resources Analysis Module analyses w...</td>
      <td>0</td>
    </tr>
    <tr>
      <th>2</th>
      <td>4DD3B04B40D227471401609D630C76ED</td>
      <td>Enterprise Manager</td>
      <td></td>
      <td>0</td>
    </tr>
  </tbody>
</table>
</div>




```python
#step 3 - Get the project ID of the project we are interested in 
# Tuorial Project (first row)

projectId = projectList.iloc[0][0]
projectId
```




    'B19DEDCC11D4E0EFC000EB9495D0F44F'




```python
#step 3 - Get the project ID of the project we are interested in 
# Tuorial Project (first row)

libraryList = mstr.getLibrary(baseURL, authToken, sessionId, 'DEFAULT')
libraryList
```




<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>id</th>
      <th>name</th>
      <th>projectId</th>
      <th>active</th>
      <th>lastViewedTime</th>
      <th>target</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>1B979449411E30E4E4502F918158EA40</td>
      <td>Category Analysis</td>
      <td>B19DEDCC11D4E0EFC000EB9495D0F44F</td>
      <td>True</td>
      <td>2018-08-11T07:49:40.000+0000</td>
      <td>512EDAA1487128DBBCA43E8525E10A11</td>
    </tr>
    <tr>
      <th>1</th>
      <td>21A521BA4DB47ADAEBE19E9E9F7EC7D9</td>
      <td>Executive Business User Data Dossier</td>
      <td>B19DEDCC11D4E0EFC000EB9495D0F44F</td>
      <td>True</td>
      <td>2018-08-10T19:36:00.000+0000</td>
      <td>FC6E8B6F4950540FC3595093E0FBA306</td>
    </tr>
    <tr>
      <th>2</th>
      <td>80AFEAD447DE2430F7E41FBB1B1EFCBA</td>
      <td>Category Breakdown Dossier</td>
      <td>B19DEDCC11D4E0EFC000EB9495D0F44F</td>
      <td>True</td>
      <td>2018-08-10T21:36:32.000+0000</td>
      <td>95005DFF4C4829CF5EE6E98877726566</td>
    </tr>
  </tbody>
</table>
</div>




```python
#Get the Target ID for the published Dossier we want to embed
# In this case I want 'Categry Analysis' first row, and I want the fifth column 'Target' id

libraryId = libraryList.iloc[0][5]
libraryId
```




    '512EDAA1487128DBBCA43E8525E10A11'



Using iPython magic cell we use `%%html` to specifiy were we want to display our Dossier. Here we load the `embeddinglib.js` JavaScript library provided by MicroStrategy. Then we add our `<script></script>` which includes our javaccript code. You can also separate the javascript in a separate cell using the `%%javascript` magic cell as well.

Dossier will be displayed right below this `%%html` cell


```python
%%html

<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
<script type="text/javascript" src="http://yourMstrEnv/MicroStrategyLibrary/javascript/embeddinglib.js"></script>
<h2> Embedding an Interactive Dossier </h2>
<div id="dossier1"></div>

<script>
//NOTE: we pass the projectID and libraryId and use them in the javaScript variables below

var project = 'B19DEDCC11D4E0EFC000EB9495D0F44F'
var library = '512EDAA1487128DBBCA43E8525E10A11'

var container = document.getElementById("dossier1"),
 
    url = "http://yourMstrEnv/MicroStrategyLibrary/app/" + project + '/' + library;
 
    microstrategy.dossier.create({
 
          url: url,
 
          enableResponsive: true,
 
          placeholder: container
       })
    
</script>
```

![image](img.PNG)

