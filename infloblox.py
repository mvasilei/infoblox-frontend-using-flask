#!/usr/bin/env python
# encoding: utf-8

import requests
import sys
import os
import re
import getpass3
import json
import string
from flask import Flask
from flask import Flask, flash, redirect, render_template, request, session, abort

request_cookies = ''
STATICFILES_DIRS = (
    'static',
)
infoblox = Flask(__name__)

# Set parameters to access the NIOS WAPI.
ADDRESS = 'https://gmcc01.bham.ac.uk/wapi/v2.5/'  # Version varies
valid_cert = False  # False since GM uses self-signed certificate
JSON = 'application/json'

@infoblox.route('/login', methods=['POST'])
def login():
    global request_cookies

    r = requests.get(ADDRESS + 'networkview',
                     auth=(request.form['username'], request.form['password']),
                     verify=valid_cert)

    # Check Credentials validity
    if r.status_code != requests.codes.ok:
        return render_template('login.html', error='Invalid Username/Password')

    # Save the authentication cookie for use in subsequent requests.
    ibapauth_cookie = r.cookies['ibapauth']
    print('Authentication cookie: ', ibapauth_cookie)
    request_cookies = {'ibapauth': ibapauth_cookie}

    return render_template('menu.html')

@infoblox.route('/searchIP', methods=['POST'])
def searchip():
    response = None
    #If button clicked = Search, proceed looking up the IP
    if request.form['submit'] == 'Search':
        # Input sanitation
        if not (re.match(r"^147.188.(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",request.form['IP'])):
            return render_template('searchIP.html', error='Invalid IP Value')

        r = requests.get(ADDRESS + 'search?address=' + request.form['IP'] + '&_return_as_object=0',
                         cookies=request_cookies,
                         verify=valid_cert)

        if r.status_code != requests.codes.ok:
            print('search_address', r.text)
            exit_msg = 'Error {} finding host by IP: {}'
            sys.exit(exit_msg.format(r.status_code, r.reason))

        response=r.json()
        print(response)

        if response:
            return render_template('Results.html', response=response)
        else:
            return render_template('Results.html', response={})
    elif request.form['submit'] == 'Menu':
        return render_template('menu.html')

    return render_template('menu.html')

@infoblox.route('/searchMAC', methods=['POST'])
def searchmac():
    if request.form['submit'] == 'Search':
        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", request.form['MAC'].lower()):
            error = 'Invalid MAC Value'
            return render_template('searchMAC.html', error=error)

        mac = request.form['MAC'].replace('-',':').lower()
        r = requests.get(ADDRESS + 'search?mac_address=' + mac + '&_return_as_object=0',
                         cookies=request_cookies,
                         verify=valid_cert)

        if r.status_code != requests.codes.ok:
            exit_msg = 'Error {} finding host by MAC: {}'
            sys.exit(exit_msg.format(r.status_code, r.reason))

        response = r.json()

        if response:
            print(response)
            for dict in response:
                if 'record:host' in dict['_ref']:
                    if dict['ipv4addrs']:
                        for item in dict['ipv4addrs']:
                            r = requests.get(ADDRESS + 'search?address=' + item['ipv4addr'] + '&_return_as_object=0',
                                         cookies=request_cookies,
                                         verify=valid_cert)
                else:
                    if dict['ipv4addr']:
                        r = requests.get(ADDRESS + 'search?address=' + dict['ipv4addr'] + '&_return_as_object=0',
                                 cookies=request_cookies,
                                 verify=valid_cert)

            response=r.json()
            print(response)

            return render_template('Results.html', response=response)
        else:
            return render_template('Results.html', response={})
    elif request.form['submit'] == 'Menu':
        return render_template('menu.html')

    return render_template('menu.html')

@infoblox.route('/addhost', methods=['POST','PUT'])
def addhost():
    #Check required fields have values
    if request.form['submit'] == 'Add':
        if not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", request.form['MAC'].lower()):
            return render_template('searchMAC.html', error='Invalid MAC Values')
        elif not (re.match(r"^147.188.(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",request.form['IP'])):
            return render_template('addHost.html', error='Invalid IP Value')
        elif not request.form['Name']:
            return render_template('addHost.html', error='Host Name is required')

            mac = request.form['MAC'].replace('-', ':')
            data = {'name': request.form['Name'],'ipv4addrs': [{"ipv4addr":request.form['IP']}],'mac_address':mac.lower(),'configure_for_dhcp': True,'view': 'default','comment':request.form['Comment']}

            r=requests.request('POST', ADDRESS + 'record:host',
                             data=json.dumps(data),
                             headers={'Content-Type': 'application/json'},
                             cookies=request_cookies,
                             verify=valid_cert)

            return render_template('addHost.html', error=r[0]['text'])
        else:
            return render_template('addHost.html', error='Host already exists')
    elif request.form['submit'] == 'Menu':
        return render_template('menu.html')

    return render_template('menu.html')

@infoblox.route('/delhost', methods=['POST','DELETE'])
def delhost():
    #Check required fields have values
    response={}
    if request.form['submit'] == 'Delete':
        if not (re.match(r"^147.188.(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",request.form['IP'])):
            return render_template('delHost.html', error='Invalid IP Value')
        elif not request.form['Name']:
            return render_template('delHost.html', error='Host Name is required')

        r = requests.get(ADDRESS + 'record:host?name~=' + request.form['Name'].lower(),
                         cookies=request_cookies,
                         verify=valid_cert)
        response=r.json()
        print(response)

        #If record exists delete it
        if len(response):
            r = requests.request('DELETE', ADDRESS + response[0]['_ref'],
                             headers={'Content-Type': 'application/json'},
                             cookies=request_cookies,
                             verify=valid_cert)

            if r.status_code != requests.codes.ok:
                return render_template('delHost.html', error='Error while deleting host ' + request.form['Name'])
            else:
                return render_template('delHost.html', error='Host ' + request.form['Name'] + ' has been deleted')
        else:
            return render_template('delHost.html', error='No host entry found')

    elif request.form['submit'] == 'Menu':
        return render_template('menu.html')

    return render_template('menu.html')

def configured_subnets():
    subnets = []

    # Query all subnets in 147.188.0.0/16
    r = requests.get(ADDRESS + 'network?network_container=147.188.0.0/16',
                     cookies=request_cookies,
                     verify=valid_cert)

    # On success create a drop down list
    if r.status_code == requests.codes.ok:
        response = r.json()

        for dict in response:
            network = dict['network']
            subnets.append(network)

        return render_template('nextAvail.html', subnets=subnets)

@infoblox.route('/nextavail', methods=['POST'])
def nextavail():
    available = ''

    r = requests.get(ADDRESS + 'network?network_container=147.188.0.0/16',
                     cookies=request_cookies,
                     verify=valid_cert)

    if r.status_code == requests.codes.ok:
        response = r.json()

        if request.method == 'POST':
            select = request.form.get('networks')
            print(select)
            if request.form['submit'] == 'Submit':
                if r.status_code == requests.codes.ok:
                    response = r.json()

                    for dict in response:

                        if str(select) in dict['_ref']:
                            headers = {
                                'content-type': 'application/json',
                            }
                            params = (
                                ('_function', 'next_available_ip'),
                                ('_return_as_object', '1'),
                            )
                            data = '{"num":1}'
                            r = requests.post(ADDRESS + dict['_ref'],
                                                     headers=headers,
                                                     params=params,
                                                     data=data,
                                                     cookies=request_cookies,
                                                     verify=valid_cert)

                            result = r.json()

                            if 'Error' in result:
                                return render_template('nextAvail.html', subnets=[], available=result['Error'])
                            else:
                                return render_template('nextAvail.html', subnets=[], available=result['result']['ips'])
            elif request.form['submit'] == 'Menu':
                return render_template('menu.html')

        return render_template('menu.html')

@infoblox.route('/results', methods=['POST'])
def results():
    if request.form['submit'] == 'Menu':
        return render_template('menu.html')

@infoblox.route('/')
def home():
    return render_template('login.html')

def logout():
    # Logout using cookie paramaters
    r = requests.post(ADDRESS + 'logout',
                      cookies = request_cookies,
                      verify = valid_cert)

    if r.status_code != requests.codes.ok:
        print(r.text)
        exit_msg = 'Error {} logging out: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))

    return render_template('login.html')

@infoblox.route('/menu', methods=['POST'])
def menu():
    if request.form['menu'] == 'Search IP':
        return render_template('searchIP.html')
    elif request.form['menu'] == 'Search MAC':
        return render_template('searchMAC.html')
    elif request.form['menu'] =='Create Host Record':
        return render_template('addHost.html')
    elif request.form['menu'] =='Delete Host Record':
        return render_template('delHost.html')
    elif request.form['menu'] =='Search Next Available IP':
        return configured_subnets()
    elif request.form['menu'] == 'Logout':
        return render_template('login.html')

    return render_template('menu.html')

def on_backbutton_clicked(self, widget):
    self.webview.go_back()

def on_forwardbutton_clicked(self, widget):
    self.webview.go_forward()

if __name__ == '__main__':
    infoblox.secret_key = os.urandom(12)
    infoblox.run(debug=True, host='0.0.0.0', port=4000, ssl_context=('cert.pem', 'key.pem'))
    logout(request_cookies)