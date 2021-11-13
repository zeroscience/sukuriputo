#!/usr/bin/env python3
#
#
# # # # # # # # # # # # # # # # # # # # # # # #
#
#  wpcsv parser script - Fletcher.251
#  lqwrm, 2021
#
# # # # # # # # # # # # # # # # # # # # # # # #
#
#
# WP changelog:
# 12.11.2021 - changed _target and drop get_em_all()
# 17.10.2021 - Added Custom Structure (Permalinks Settings), %category%/%postname%, using category: advisory. (changed)--+
# 15.10.2021 - Removed tagged URL in Category Base (Permalinks Settings), old value: advisory. (errors fixed) <----------+
# 

import re, sys, requests
from alive_progress import alive_bar, config_handler

config_handler.set_global(length=65,spinner='dots_waves')
VERSION='1.9p-beta'
DEBUG=False

bn='''\
 _____ _     _       _             ___ ___ ___   
|   __| |___| |_ ___| |_ ___ ___  |_  |  _|_  |  
|   __| | -_|  _|  _|   | -_|  _|_|  _|_  |_| |_ 
|__|  |_|___|_| |___|_|_|___|_| |_|___|___|_____|
'''
print(bn)
print('Version:',VERSION, end='\n')

_target=None

#All advisories
def get_em_all():
    pass # get_by year xref

#All titles
def get_titles():
    r=requests.get(_target)
    z=re.findall(r'hp">(.*?)</a', r.text, re.DOTALL)
    for n, t in enumerate(z):
        print('{0:4}{1:3}{2:3}'.format(str(n).zfill(3), '->', t))
        with open('titles.txt', 'a', encoding='utf8') as f:
            f.write(t+'\n')
    sys.exit()

def get_by_year():
    yearinput=input('Enter "cve", year [2008-2021], "titles" or "all": ')
    if '2021' in yearinput:
        rangee=range(5614,5688)
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
    elif 'all' in yearinput:
        get_em_all()
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
            r = requests.get(_target+str(yearinput)+'-'+str(i)+'.php')
            if '200' not in str(r.status_code):
                raise Exception('Fetch error.')
        
            #Title
            t = re.search(r'Title: (.*?)<br />', r.text).group(1)
            
            #Advisory ID
            adid = re.search(r'Advisory ID: <a href="(.*?).php', r.text).group(1)

            #Risk
            risk = re.search(r'Risk: (.*?)<br', r.text, re.DOTALL).group(1)
            if risk == '(5/5)' or risk =='(4/5)':
                risk = '"img/high.png"'
            if risk == '(3/5)':
                risk = '"img/medium.png"'
            if risk == '(2/5)' or risk =='(1/5)':
                risk = '"img/low.png"'

            #Impact
            impact = re.search(r'Impact: (.*?)<br', r.text, re.DOTALL).group(1)
    
            #Vendor
            vendor = re.search(r'Vendor<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1).replace('\n', '')
            vendor = re.sub(r'\s+', ' ', vendor).strip()
    
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
            #remcode = lambda c: c.split('<code>')[0] + c.split('</code>')[-1]
            #finaldes=(remcode(finaldes)).replace('-','') # pazi na ovakvi-zborovi
            #finaldes=finaldes.replace('<br><br>','').strip().removesuffix('<br>')
            junk = '<br><br> -'
            s_desc = desc.split(junk, 1)[0].replace('<br><br> ', '<br><br>')
            #print(s_des.removesuffix('<br>'))

            #Tested on
            tstd = re.search(r'Tested On<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            tstd = re.sub(r'\s+', ' ', tstd).strip()
            tstd = re.sub(r'<br /> ', '<br>', tstd)
    
            #Vendor Status
            venst = re.search(r'Status<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            venst = re.sub(r'\s+', ' ', venst).strip()
            venst = re.sub(r'<br /> ', '<br>', venst)
    
            #PoC  -data-type=""URL""
            finalpoc = re.search(r'PoC<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            finalpoc = re.sub(r'../../codes', '/codes', finalpoc)
            finalpoc = re.sub(r'\s+', ' ', finalpoc).strip()
            finalpoc = re.sub(r'<br /> ', '<br>', finalpoc)
    
            #Credits
            credit = re.search(r'Credits<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            credit = re.sub(r'\s+', ' ', credit).strip()
            credit = re.sub(r'<br /> ', '<br>', credit)
    
            #References
            refs = re.search(r'References<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            refs = re.sub(r'\s+', ' ', refs).strip()
            refs = re.sub(r'<br /> ', '<br>', refs)
    
            #Changelog
            chglog = re.search(r'Changelog<\/h5>(.*?)<h5>', r.text, re.DOTALL).group(1)
            chglog = re.sub(r'\s+', ' ', chglog).strip()
            chglog = re.sub(r'<br /> ', '<br>', chglog)

            begwp = '<!-- wp:paragraph -->'
            endwp = '<!-- /wp:paragraph -->'
            paragS = '<p>'
            paragE = '</p>'
    
            #Write as post
            # -> as func()
            with open('testingus.csv', 'a', encoding='utf8') as f:
                f.write('"'+t+'","149","')
                f.write('<!-- wp:separator {""customColor"":""#ff0000"",""className"":""is-style-dots""} --><hr class=""wp-block-separator has-text-color has-background is-style-dots"" style=""background-color:#ff0000;color:#ff0000""/>\n<!-- /wp:separator -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+'<strong>Advisory ID:</strong> '+adid+'<br><strong>_vendor</strong>vname -&nbsp;<a rel=""noreferrer noopener"" href=""http://www.none/"" target=""_blank"">http://www.none</a><br><strong>Release date:</strong> '+rdate+'<br><strong>Impact:</strong> '+impact+'<br><strong>Risk:</strong> <img class=""wp-image-88"" style=""width: 50px;"" src="'+risk+'" alt=""""> <img class=""wp-image-85"" style=""width: 70px;"" src="'+risk+'" alt=""""> <img class=""wp-image-83"" style=""width: 90px;"" src="'+risk+'" alt="""">'+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>Summary</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+summ+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>Description</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+s_desc+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>Affected version</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+afver+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>Tested on</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+tstd+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>Vendor status</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+venst+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>Proof of Concept</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+finalpoc+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>Credits</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+credit+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>References</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+refs+paragE+'\n'+endwp)
                f.write('\n\n')
                f.write('<!-- wp:heading {""level"":5} -->\n')
                f.write('<h5>Changelog</h5>\n')
                f.write('<!-- /wp:heading -->')
                f.write('\n\n')
                f.write(begwp+'\n'+paragS+chglog+paragE+'\n'+endwp)
                f.write('",,"2021-10-13 13:37:00","'+adid+'","user","publish",,"advisories",,"contained","default","left","[""title"",""meta"",""thumbnail"",""content"",""tags"",""post-navigation""]"')
                f.write('\n')
            #print('Advisory:',i,'[Complete]')
    
        print(f'File closed: {f.closed}')

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
                r=requests.get(_target+str(years)+'-'+str(o)+'.php')
                if '200' not in str(r.status_code):
                    raise Exception('Fetch error.')
                cve_id = re.search(r'\?name=(.*?)"', r.text, re.DOTALL)
                title = re.search(r'Title: (.*?)<br />', r.text).group(1)
                if cve_id:
                    if not 'CVE' in cve_id.group(1):
                        cve_id='CVE-'+cve_id.group(1)
                    else:
                        cve_id=cve_id.group(1) #.sort() ama ne treba :P
                    with open('cve_list.txt', 'a', encoding='utf8') as f:
                        f.write(cve_id+'-'+title+'\n')
    
    print(f'File closed: {f.closed}')
    sys.exit()

def main():
    get_by_year()

if __name__ == '__main__':
    main()
