#!/usr/bin/env python3
#
#
# # # # # # # # # # # # # # # # # # # # # # # #
#                                             #
#  ZSL's WP parser script - Fletcher.251      #
#                                             #
#  (c) 2021                                   #
#                                             #
# # # # # # # # # # # # # # # # # # # # # # # #
#
#
# Changenote:
# 07.12.2021 - Used WP REST API. Refactored <----------------------------------------------------------------------------+
# 17.10.2021 - Added Custom Structure (Permalinks Settings), %category%/%postname%, using category: advisory. (changed)--+
# 17.10.2021 - Removed tagged URL in Category Base (Permalinks Settings), old value: advisory. (errors fixed) <----------+
# 

import re
import sys
from alive_progress import alive_bar, config_handler
import base64
import requests

VERSION='3.1g-beta'
DEBUG=False

config_handler.set_global(length=65,spinner='dots_waves')

bn='''\
 _____ _     _       _             ___ ___ ___   
|   __| |___| |_ ___| |_ ___ ___  |_  |  _|_  |  
|   __| | -_|  _|  _|   | -_|  _|_|  _|_  |_| |_ 
|__|  |_|___|_| |___|_|_|___|_| |_|___|___|_____|
'''
print(bn)
print('Version:',VERSION, end='\n')

#All advisories titles
def get_titles():
    r=requests.get('https://www.zeroscience.mk/en/vulnerabilities/')
    z=re.findall(r'hp">(.*?)</a', r.text, re.DOTALL)
    for n, t in enumerate(z):
        print('{0:4}{1:3}{2:3}'.format(str(n).zfill(3), '->', t))
        with open('titles.txt', 'a', encoding='utf8') as f:
            f.write(t+'\n')
    sys.exit()

def get_by_year():
    yearinput=input('Enter "cve", year [2008-2021], "titles": ')
    if '2021' in yearinput:
        rangee=range(5614,5689)
    elif '2020' in yearinput:
        rangee=range(5561,5614)
    elif '2019' in yearinput:
        rangee=range(5502,5561)
    elif '2018' in yearinput:
        rangee=range(5448,5502)
    elif '2017' in yearinput:
        rangee=range(5393,5448)
    elif '2016' in yearinput:
        rangee=range(5291,5393)
    elif '2015' in yearinput:
        rangee=range(5218,5291)
    elif '2014' in yearinput:
        rangee=range(5165,5218)
    elif '2013' in yearinput:
        rangee=range(5121,5165)
    elif '2012' in yearinput:
        rangee=range(5066,5121)
    elif '2011' in yearinput:
        rangee=range(4986,5066)
    elif '2010' in yearinput:
        rangee=range(4925,4986)
    elif '2009' in yearinput:
        rangee=range(4903,4925)
    elif '2008' in yearinput:
        rangee=range(4891,4903)
    elif 'titles' in yearinput:
        get_titles()
    elif 'cve' in yearinput:
        cve()
    else:
        print('No no no.')
        sys.exit()
    
    print('Fetching year', yearinput)
    with alive_bar(len(rangee), bar='solid') as barche:
        for i in reversed(rangee):
            barche()
            r = requests.get('https://www.zeroscience.mk/en/vulnerabilities/ZSL-'+str(yearinput)+'-'+str(i)+'.php')
            if '200' not in str(r.status_code):
                raise Exception('Fetch error.')

            #Title
            t = re.search(r'Title: (.*?)<br />', r.text).group(1)
            
            #Advisory ID
            adid = re.search(r'Advisory ID: <a href="(.*?).php', r.text).group(1)

            #Risk
            risk = re.search(r'Risk: (.*?)<br', r.text, re.DOTALL).group(1)
            if risk == '(5/5)' or risk =='(4/5)':
                risk = '"/images/high.png"'
            if risk == '(3/5)':
                risk = '"/images/medium.png"'
            if risk == '(2/5)' or risk =='(1/5)':
                risk = '"/images/low.png"'

            #Impact
            impact = re.search(r'Impact: (.*?)<br', r.text, re.DOTALL).group(1)
    
            #Vendor
            vendor = re.search(r'Vendor<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1).replace('\n', '')
            vendor = re.sub(r'\s+', ' ', vendor).strip()
            vendor_name = re.search(r'(.*?)<a ', vendor).group(1)
            vendor_url = re.search(r'ref="(.*?)"', vendor).group(1)
            vendor = vendor_name+'<a href="'+vendor_url+'" target="_blank">'+vendor_url+'</a>'
    
            #Release date
            rdate = re.search(r'Release Date: (.*?)<br', r.text, re.DOTALL).group(1)
    
            #Affected version
            afver = re.search(r'Version<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            afver = re.sub(r'\s+', ' ', afver).strip()
            afver = re.sub(r'<br /> ', '<br>', afver)
    
            #Summary
            summ = re.search(r'Summary<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1).replace('\n', ' ')
            summ = re.sub(r'\s+', ' ', summ).strip()
            summ = re.sub(r'<br />', '<br>', summ)
            summ = re.sub(r'<br> <br> ', '</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p>', summ)
            summ = re.sub(r'<br><br> ', '</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p>', summ)
            
            #Description
            desc = re.search(r'Description<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1).replace('\n', ' ')
            desc = re.sub(r'\s+', ' ', desc).strip()
            desc = re.sub(r'<br />', '<br>', desc)
            junk = '<br><br> -'
            s_desc = desc.split(junk, 1)[0].replace('<br><br> ', '<br><br>')

            #Tested on
            tstd = re.search(r'Tested On<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            tstd = re.sub(r'\s+', ' ', tstd).strip()
            tstd = re.sub(r'<br /> ', '<br>', tstd)
    
            #Vendor Status
            venst = re.search(r'Status<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            venst = re.sub(r'\s+', ' ', venst).strip()
            venst = re.sub(r'<br /> ', '<br>', venst)
    
            #PoC
            finalpoc = re.search(r'PoC<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            finalpoc = re.sub(r'../../codes', '/codes', finalpoc)
            finalpoc = re.sub(r'\s+', ' ', finalpoc).strip()
            finalpoc = re.sub(r'<br /> ', '<br>', finalpoc)
            finalpoc_rest = re.search(r'ref="(.*?)"', finalpoc).group(1)
            finalpoc_show = re.search(r'lank">(.*?)</a>', finalpoc).group(1)
            finalpoc = '<a href="'+finalpoc_rest+'" target="_blank">'+finalpoc_show+'</a>'
    
            #Credits
            credit = re.search(r'Credits<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            credit = re.sub(r'\s+', ' ', credit).strip()
            credit = re.sub(r'<br /> ', '<br>', credit)
            credit = re.search(r'(.*?) - ', credit).group(1)
    
            #References
            refs = re.search(r'References<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            refs = re.sub(r'\s+', ' ', refs).strip()
            refs = re.sub(r'<br /> ', '<br>', refs)
            refs = refs.replace('] <', ']&nbsp;<')
    
            #Changelog
            chglog = re.search(r'Changelog<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            chglog = re.sub(r'\s+', ' ', chglog).strip()
            chglog = re.sub(r'<br /> ', '<br>', chglog)

            begwp = '<!-- wp:paragraph -->'
            endwp = '<!-- /wp:paragraph -->'
            paragS = '<p>'
            paragE = '</p>'
    
            #WP REST API
            rest_url = "https://www.zeroscience.mk/XXXX/wp-json/wp/v2/posts"
            wp_user = "zsltest"
            wp_app_pwd = "XXXX XXXX XXXX XXXX XXXX XXXX"
            wp_auth = wp_user + ':' + wp_app_pwd
            api_token = base64.b64encode(wp_auth.encode())
            api_header = {'Authorization': 'Basic ' + api_token.decode('utf-8')}

            content  = paragS+paragE
            content += begwp+'\n'+paragS+'<strong>Advisory ID:</strong> '+adid+'&nbsp;<br>'
            content += '<strong>Vendor:</strong> '+vendor+'&nbsp;<br>'
            content += '<strong>Release date:</strong> '+rdate+'&nbsp;<br>'
            content += '<strong>Impact:</strong> '+impact+'&nbsp;<br>'
            content += '<strong>Risk:</strong> <img style="width: 50px;" src='+risk+' alt=""> <img style="width: 50px;" src='+risk+' alt=""> <img style="width: 50px;" src='+risk+' alt="">'+paragE+'\n'+endwp
            content += begwp+'\n'+paragS+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>Introduction</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+summ+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>Description</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+s_desc+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>Affected version</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+afver+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>Tested on</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+tstd+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>Vendor status</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+venst+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>Proof of Concept</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+finalpoc+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>Credits</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+credit+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>References</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+refs+paragE+'\n'+endwp
            content += '<!-- wp:heading {""level"":5} -->\n'
            content += '<h5>Changelog</h5>\n'
            content += '<!-- /wp:heading -->'
            content += begwp+'\n'+paragS+chglog+paragE+'\n'+endwp

            wp_post = {'title'     : t,
                       'status'    : 'publish',
                       'slug'      : adid,
                       'content'   : content,
                       'categories': 4, # advisories, lablog id
                       #'featured_media' : 2,
                       'date'      : '2021-12-08T13:37:00'
                      }
            requests.post(rest_url, headers=api_header, json=wp_post)

def cve():
    for years in reversed(range(2008,2022)):
        if years == 2021:
            rangee=range(5614,5688)
        if years == 2020:
            rangee=range(5561,5614)
        if years == 2019:
            rangee=range(5502,5561)
        if years == 2018:
            rangee=range(5448,5502)
        if years == 2017:
            rangee=range(5393,5448)
        if years == 2016:
            rangee=range(5291,5393)
        if years == 2015:
            rangee=range(5218,5291)
        if years == 2014:
            rangee=range(5165,5218)
        if years == 2013:
            rangee=range(5121,5165)
        if years == 2012:
            rangee=range(5066,5121)
        if years == 2011:
            rangee=range(4986,5066)
        if years == 2010:
            rangee=range(4925,4986)
        if years == 2009:
            rangee=range(4903,4925)
        if years == 2008:
            rangee=range(4891,4903)
        with alive_bar(len(rangee), bar='solid') as barche:
            for o in reversed(rangee):
                barche()
                r=requests.get('http://www.zeroscience.mk/en/vulnerabilities/ZSL-'+str(years)+'-'+str(o)+'.php')
                if '200' not in str(r.status_code):
                    raise Exception('Fetch error.')
                cve_id = re.search(r'\?name=(.*?)"', r.text, re.DOTALL)
                title = re.search(r'Title: (.*?)<br />', r.text).group(1)
                if cve_id:
                    if not 'CVE' in cve_id.group(1):
                        cve_id='CVE-'+cve_id.group(1)
                    else:
                        cve_id=cve_id.group(1) #.sort() ama ne treba :P
                    with open('CVE_list.txt', 'a', encoding='utf8') as f:
                        f.write(cve_id+'-'+title+'\n')
    
    print(f'File closed: {f.closed}')
    sys.exit()

def main():
    get_by_year()

if __name__ == '__main__':
    main()
