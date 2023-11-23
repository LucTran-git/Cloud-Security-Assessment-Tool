# Cloud-Security-Assessment-Tool

<h2>OVERVIEW OF WORKINGS</h2>  
This tool assesses the posture of your AWS account by performing security checks for focused on specific services, and outputting log files and graphs based on these findings.

It is separated into 3 rounds of analysis:
1. Manual checks (finding specific errors)    
    - Outputs log files to archive all errors found (txt or json)  
2. Machine learning (finding general trends in errors)    
    - Outputs bar graphs for ML-based analysis         
3. Miscellaneous   
    - Outputs bar graphs for non-ML analysis  

In the manual checks round, it checks for possible errors to create warnings. These warnings explain (in text) why the possible error could compromise security, and gives recommendations to fix them.  

In the machine learning round, the texts in the warnings generated in the previous round are analyzed for keywords. The keywords are outputted in horizontal bar graphs.  

In the last round, some other bar graphs are outputted based on the more easily categorizable characteristics that don't require ML, such as the service a warning is attributed to.  

<h2>TO USE</h2>

First, get your AWS access key:  
1. After logging into AWS, click your name, then security credentials  
2. Click on "Create Access Key"   
3. Enter the credentials shown into their corresponding places in 'Credentials.json' file  
    
Then, you can run the program
<h3>RUNNING ON WINDOWS</h3>  

1. Open command prompt in the folder 'cloudtool.py' is located in
2. Type 'python cloudtool.py'  
    - Note: You may have to install various modules:  
      - boto3
      - botocore
      - matplotlib
      - yake  
    - You can install these modules using pip  
3. Follow instructions printed to the cmd line

All output files (txt/json for written output, png for graphs) will be printed under the 'logs' folder in the same directory. 
