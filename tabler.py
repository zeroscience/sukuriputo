#!/usr/bin/env python3
#

import re
from alive_progress import alive_bar, config_handler
import base64
import requests

def autolist():
    paragS = '<p>'
    paragE = '</p>'
    content = paragS+paragE
    for years in reversed(range(2008,2022)):
        if years == 2021:
            rangee=range(5614,5689)
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
    
        content += paragS+paragE
        content += '<h2>'+str(years)+'</h2>'
        content += paragS+paragE
        content += '<figure class="wp-block-table alignwide is-style-stripes"><table class="has-text-color has-background" style="color:#415568"><tbody>'
        with alive_bar(len(rangee), bar='solid') as barche:
            for i in reversed(rangee):
                barche()
                r = requests.get('https://www.zeroscience.mk/en/vulnerabilities/ZSL-'+str(years)+'-'+str(i)+'.php')
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
    
                #Release date
                rdate = re.search(r'Release Date: (.*?)<br', r.text, re.DOTALL).group(1)
    
                #WP REST API
                rest_url = "https://www.zeroscience.mk/XXXX/wp-json/wp/v2/pages/5151" # Update existing page 'tabela', id:5151.
                wp_user = "usuario"
                wp_app_pwd = "jjjj jjjj jjjj jjjj jjjj jjjj"
                wp_auth = wp_user + ':' + wp_app_pwd
                api_token = base64.b64encode(wp_auth.encode())
                api_header = {'Authorization': 'Basic ' + api_token.decode('utf-8')}
    
                content += '<tr><td>'+rdate+'</td><td class="has-text-align-left" data-align="left"><img style="width: 50px;" src='+risk+' alt=""></td><td>'
                content += '<a href="https://www.zeroscience.mk/XXXX/advisories/'+adid+'">'+t+'</a></td><td>'+adid+'</td></tr>'
    
        content += '</tbody></table></figure>'
    wp_post = {'title'     : 'tabela',
               'status'    : 'publish',
               'slug'      : 'tabela',
               'content'   : content,
               'date'      : '2021-12-06T13:37:00'}
    requests.post(rest_url, headers=api_header, json=wp_post)

def main():
    autolist()

if __name__ == '__main__':
    main()
