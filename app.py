from flask import Flask, render_template, url_for, redirect,request, abort
from werkzeug.utils import secure_filename
import os
import pefile
import csv
import array
import math
import joblib
import pandas as pd
import numpy as np

app=Flask(__name__)
app.config['SECRET_KEY']='a968f87af924f50ad1edc9bc42ea3010'
app.config['MAX_CONTENT_LENGTH']= 1024*1024*1024
app.config['UPLOAD_EXTENSIONS']= ['.exe','.dll']
app.config['UPLOAD_PATH']= 'uploads' 
app.config['EXTRACT_INFO']='csv_files'

@app.route('/',methods=['GET','POST'])
def hello():
     if request.method == 'POST':
      return render_template("home.html")
     else:
      return render_template("intro.html")


@app.route('/about')
def about():
    return render_template("about.html",title='About')

    
@app.route('/home')
def home():
    return render_template("home.html")

@app.route('/team')
def team():
    return render_template("team.html")


@app.route('/index')
def index():
    dir = app.config['UPLOAD_PATH']
    files = os.listdir(dir) 
    return render_template('upload.html', upfiles = files)
  
@app.route('/index', methods=['POST'])
def upload_file():
    uploaded_file = request.files.get('file')
    filename = secure_filename(uploaded_file.filename)
    if filename!= '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            abort(400)
        path = os.path.join(app.config['UPLOAD_PATH'],filename)
        uploaded_file.save(path)
        return redirect(url_for('index'))
      

@app.errorhandler(413)
def too_large(e):
    return render_template('err_too_big.html')
 

def get_entropy(data):
    if len(data) == 0:
	       return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
  	    occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
	    if x:
	       p_x = float(x) / len(data)
	       entropy -= p_x*math.log(p_x, 2)

    return entropy

@app.route('/extract',methods=['GET', 'POST'])
def extract():
    # collecting filepaths
    file_paths = []
    dir=app.config['UPLOAD_PATH']
    for root, directories, files in os.walk(dir):
        for filename in files:
            # Join the two strings in order to form the full filepath.
            path = os.path.join(root,filename)
            file_paths.append(path)
         

    # using filepaths to extract file info
    global myList
    myList = []
    for i in file_paths:
        fpath = i
        
        # pefiles info
        try:
            pe = pefile.PE(name=fpath)
      
        except OSError as e:
               print(e)
        except pefile.PEFormatError as e:
               print("[-] PEFormatError: %s" % e.value)
        
        # Sections
        entropy = map(lambda x:x.get_entropy(), pe.sections)
        SectionsMinEntropy = min(entropy)
        raw_sizes = map(lambda x:x.SizeOfRawData, pe.sections)
        SectionsMinRawsize = min(raw_sizes)
        virtual_sizes = map(lambda x:x.Misc_VirtualSize, pe.sections)
        SectionsMinVirtualsize = min(virtual_sizes)
        raw_data = map(lambda x:x.PointerToRawData, pe.sections)
        SectionMaxPointerData = max(raw_data)

        #directory
        DirectoryEntryImportSize = len(sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], []))
        try:
          DirectoryEntryExport = pe.DIRECTORY_ENTRY_EXPORT.symbols
          DirectoryEntryExport = len(DirectoryEntryExport)
        except AttributeError:
          DirectoryEntryExport = 0
        
        #imagedirectories
        ImageDirectoryEntryExport = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
        ImageDirectoryEntryImport = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ImageDirectoryEntrySecurity = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        
        # Adding multiple key value pairs
        myList.append({ 
                        'Machine':pe.FILE_HEADER.Machine,
                        'Characteristics':pe.FILE_HEADER.Characteristics,
                        'MajorLinkerVersion':pe.OPTIONAL_HEADER.MajorLinkerVersion,
                        'MinorLinkerVersion':pe.OPTIONAL_HEADER.MinorLinkerVersion,
                        'SizeOfCode':pe.OPTIONAL_HEADER.SizeOfCode,
                        'SizeOfInitializedData':pe.OPTIONAL_HEADER.SizeOfInitializedData,
                        'AddressOfEntryPoint':pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                        'ImageBase':pe.OPTIONAL_HEADER.ImageBase,
                        'MajorOperatingSystemVersion':pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                        'MinorOperatingSystemVersion':pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                        'MajorImageVersion':pe.OPTIONAL_HEADER.MajorImageVersion,
                        'MinorImageVersion':pe.OPTIONAL_HEADER.MinorImageVersion,
                        'MajorSubsystemVersion':pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                        'MinorSubsystemVersion':pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                        'SizeOfHeaders':pe.OPTIONAL_HEADER.SizeOfHeaders,
                        'CheckSum':pe.OPTIONAL_HEADER.CheckSum,
                        'SizeOfImage':pe.OPTIONAL_HEADER.SizeOfImage,
                        'Subsystem':pe.OPTIONAL_HEADER.Subsystem,
                        'DllCharacteristics':pe.OPTIONAL_HEADER.DllCharacteristics,
                        'SizeOfStackReserve':pe.OPTIONAL_HEADER.SizeOfStackReserve,
                        'SectionMinEntropy':SectionsMinEntropy,
                        'SectionMinRawsize':SectionsMinRawsize,
                        'SectionMinVirtualsize':SectionsMinVirtualsize,
                        'SectionMaxPointerData':SectionMaxPointerData,
                        'DirectoryEntryImportSize':DirectoryEntryImportSize,
                        'DirectoryEntryExport':DirectoryEntryExport,
                        'ImageDirectoryEntryExport':ImageDirectoryEntryExport,
                        'ImageDirectoryEntryImport':ImageDirectoryEntryImport,
                        'ImageDirectoryEntrySecurity':ImageDirectoryEntrySecurity
                        })
        pe.close()
        
       

    #column names are stored in list
    csv_columns = [ 'Machine','Characteristics','MajorLinkerVersion',
                    'MinorLinkerVersion','SizeOfCode','SizeOfInitializedData','AddressOfEntryPoint',
                    'ImageBase','MajorOperatingSystemVersion','MinorOperatingSystemVersion',
                    'MajorImageVersion','MinorImageVersion','MajorSubsystemVersion',
                    'MinorSubsystemVersion','SizeOfHeaders','CheckSum','SizeOfImage',
                    'Subsystem','DllCharacteristics','SizeOfStackReserve',
                    'SectionMinEntropy','SectionMinRawsize','SectionMinVirtualsize',
                    'SectionMaxPointerData','DirectoryEntryImportSize','DirectoryEntryExport',
                    'ImageDirectoryEntryExport','ImageDirectoryEntryImport','ImageDirectoryEntrySecurity']
    
    #writing values to extract.csv located in csv_files directory
    csv_file = app.config['EXTRACT_INFO']+"extract.csv"
    try:
        with open(csv_file,'w',newline='') as csvfile:
            writer = csv.DictWriter(csvfile,fieldnames=csv_columns)
            writer.writeheader()
            for data in myList:
                writer.writerow(data)
    except IOError:
        print("I/O error")

    fieldnames = [key for key in myList[0].keys()]
    
            
    return render_template('extraction.html', myList=myList , fieldnames=fieldnames,len=len) 

#deleting all the files in uploads directory
@app.route('/delete',methods=['GET', 'POST'])
def delete():
    # Directory name 
    dir = app.config['UPLOAD_PATH']
    files = os.listdir(dir)
    for f in files:
        os.remove(os.path.join(dir, f))

    return redirect(url_for('index'))



def filename(path):
    file_list=[]
    files = os.listdir(path)
    for f in files:
	    file_list.append(f)   
    return file_list

# detecting the target label of files
@app.route('/predictions', methods=['GET','POST'])
def predictions():

    input = pd.read_csv(app.config['EXTRACT_INFO']+"extract.csv")
    for feature in input.columns:
        input[feature]=np.log1p(input[feature])

    path = app.config['UPLOAD_PATH']

    if request.method == 'POST':
        if request.form.get('algo1') == 'Random_Forest':
           model = joblib.load('RF_model') 
           res = model.predict(input)
           f_name = filename(path)
           return render_template('predictions.html',res = res,f_name = f_name)
           
        elif(request.form.get('algo2') == 'Logistic_Regression'):
             lrmodel = joblib.load('LR_model') 
             res = lrmodel.predict(input)
             f_name = filename(path)
             return render_template('predictions.html',res = res,f_name = f_name)
        else:
             knmodel = joblib.load('KN_model') 
             res = knmodel.predict(input)
             f_name = filename(path)
             return render_template('predictions.html',res = res,f_name = f_name)
            
        
    else:
        return render_template('predictions.html')


if __name__=='__main__':
    app.run(debug=1)  
