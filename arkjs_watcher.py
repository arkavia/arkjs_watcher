#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Owned
__author__ = "JUAN CERPA"
__copyright__ = "Copyright 2019, The Cogent Project"
__license__ = "GPL"
__version__ = "1.0.0"
__credits__ = ["JUAN CERPA","CRISTIAN ALARCON", "ARKAVIA NETWORKS"]
__maintainer__ = "JUAN CERPA"
__email__ = "juan.cerpa@arkavia.com"
__status__ = "Production"

import requests
import configparser
import os
from bs4 import BeautifulSoup
import wget
import ssl
import calendar
import time
import json, urllib, argparse, hashlib, re, sys, urllib.parse
from urllib.request import urlopen
import cli_ui
from termcolor import cprint 
from pyfiglet import figlet_format


# VARIABLES GLOBALES
cprint(figlet_format('arkjs',font='larry3d'),"blue",attrs=["bold"])
cprint(figlet_format('by Arkavia Networks',font='threepoint'),"green",attrs=["bold"])
current_path = os.getcwd()
vt_count = 0
vt_upload_count = 0


# TABLA DETALLE
data_final = []
headers=["NOMBRE JS", "HASH" , "DETECCIONES","URL VIRUS TOTAL"]
headers_vt_files=["NOMBRE JS", "HASH","URL VIRUS TOTAL"]
data_files_vt = []

# OBTENER VARIABLES DE CONFIGURACION #
config = configparser.ConfigParser()
config.read(current_path+"/"+'config.ini')
vt_apikey = config['DEV']['vt_apikey']
vt_url_scan_report = config['DEV']['vt_url_scan_report']
vt_url_post_file = config['DEV']['vt_url_post_file']
vt_user_agent = config['DEV']['vt_user_agent']
sc_path_reports = config['DEV']['sc_path_reports']
vt_sleep_post_file = config['DEV']['vt_sleep_post_file']
vt_sleep_scan_report = config['DEV']['vt_sleep_scan_report']

# DEFINICION DE ARGUMENTOS DE SCRIPT #
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', action='store', dest='url', help='URL a analizar')
parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0.0')
results = parser.parse_args()


def vTotalQuery(sha256):
    params = {"apikey": vt_apikey, "resource": str(sha256)}
    headers = {
        "Accept-Encoding": "identity, deflate, compress, gzip",
        "User-Agent" : vt_user_agent
    }
    time.sleep(int(vt_sleep_scan_report))
    response = requests.get(vt_url_scan_report, params=params, headers=headers)
    json_response = "ERROR"    
    if(response.status_code == 200):
        json_response = response.json()
    
    return (json_response)

def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    cwd = current_path+"/"+str(filename)
    with open(str(cwd), 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

def filename(item):
    matchObj = re.match( r'.*\/(.*)', item, re.M|re.I)
    if matchObj:
        myfile = matchObj.group(1)
    else:
        myfile = item
    return myfile

def clearURL(item):
    matchObj = re.match( r'//(.*)', item, re.M|re.I)
    if matchObj:
        newURL = matchObj.group(1)
    else:
        newURL = item
    return newURL

def clearJS(item):
    matchObj = re.match( r'(.*.js).*', item, re.M|re.I)
    if matchObj:
        urljs = matchObj.group(1)
    else:
        urljs = item
    return urljs

def generateUrl(item):
    matchObj = re.match( r'(https?:\/\/[^\/]+([.]cl|com)?)', item, re.M|re.I)
    if matchObj:
        newURL = matchObj.group(1)
    else:
        newURL = item
    return newURL

def verifyJS(url, dirname):
    count_items = 0
    global vt_count
    ssl._create_default_https_context = ssl._create_unverified_context
    r  = requests.get(url) 
    soup = BeautifulSoup(r.content,features="lxml")
    try: 
        os.mkdir(sc_path_reports+"/"+str(dirname))
        cli_ui.info_3("Directory " , dirname ,  " Created ") 
    except FileExistsError:
        cli_ui.info_3("Directory " , dirname ,  " already exists")    
 
    lista = [i.get('src') for i in soup.find_all('script') if i.get('src')] 
    
     
    
    for item in lista:        
        item = clearJS(item)
        myfile=filename(item)
        newURL = clearURL(item) ## elimina // en url inicial
        if newURL.startswith('/'):
            newURL =  generateUrl(url) + newURL
        try:
            os.system("wget -q -U='"+vt_user_agent+"' -O '"+sc_path_reports+"/{0}' {1}".format(str(dirname)+"/"+myfile,newURL))
            pathfile = sc_path_reports+"/"+str(dirname)+"/"+str(myfile)            
            sha256 = sha256sum(pathfile)
            result = (vTotalQuery(sha256))
            if(result!='ERROR'):   
                if(result['response_code'] == 1): 
                    permalink = (result['permalink'])
                    total = (result['total'])
                    positives = (result['positives'])
                    if(positives > 0):
                        vt_count+=1 
                        data = [
                                [   
                                    (cli_ui.blue,str(myfile)),
                                    (cli_ui.blue,str(sha256)),
                                    (cli_ui.blue,str(positives)+"/"+str(total)),
                                    (cli_ui.blue,str(permalink))
                                ]
                            ]

                        data_final.extend(data)
                else:
                    params = {"apikey": vt_apikey, "resource": str(sha256)}
                    headers = {
                        "Accept-Encoding": "identity, deflate, compress, gzip",
                        "User-Agent" : vt_user_agent
                    }
                    files = {'file': (pathfile, open(pathfile, 'rb'))}
                    time.sleep(int(vt_sleep_post_file))
                    response = requests.post(vt_url_post_file, files=files, params=params)
                    json_response = response.json()
                    data = [
                                [   
                                    (cli_ui.blue,str(myfile)),
                                    (cli_ui.blue,str(sha256)),
                                    (cli_ui.blue,str(json_response['permalink']))
                                ]
                            ]

                    data_files_vt.extend(data)       

            else:
                cli_ui.error("ERROR AL CONSULTAR, VALIDAR API")
            count_items+=1
            cli_ui.info_progress("Done", count_items, len(lista))
        except Exception as e:
            cli_ui.error(str(e))


 
if __name__ == "__main__": 
    if(results.url):
        try: 
            os.mkdir(sc_path_reports)
            cli_ui.info_3("Directory " , sc_path_reports ,  " Created ") 
        except FileExistsError:
            cli_ui.info_3("Directory " , sc_path_reports ,  " already exists")

        ts = calendar.timegm(time.gmtime())         
        verifyJS(results.url,ts)
        print('\n' * 2)
        cli_ui.info_section("RESULTADO")
        cli_ui.info_1("URL: "+ str(results.url))
        cli_ui.info_1("ARCHIVOS ENCONTRADOS EN VIRUS TOTAL: "+str(vt_count))
        
        if(vt_count>0):
            print('\n' * 2)
            cli_ui.info_section("DETALLE")
            cli_ui.info_table(data_final, headers=headers)

        if(vt_upload_count>0):
            print('\n' * 2)
            cli_ui.info_section("DETALLE ARCHIVOS ENVIADOS A VIRUS TOTAL")
            cli_ui.info(cli_ui.darkblue, "NOTA: ESTOS ARCHIVOS HAN SIDO ENVIADOS A ANALIZAR A VIRUS TOTAL.")

            cli_ui.info_table(data_files_vt, headers=headers_vt_files)
    else:
        cli_ui.warning('No option was selected. To check CLI options, run script in help mode: \'{} -h\''.format(__file__))
 
   
    
