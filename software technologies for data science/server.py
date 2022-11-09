#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie # some cookie handling support
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import json # support for json encoding
import sys # needed for agument handling
from datetime import datetime
import time
import sqlite3
import uuid
import itertools
from math import ceil

import csv
import pandas as pd
import numpy as np
from collections import defaultdict

#/usr/local/bin/python3.9 "/Users/zoe/Downloads/code 3/og_server.py"
# /Users/zoe/opt/anaconda3/bin/python "/Users/zoe/labs/traffic app/traffic app code/og_server.py" 8081



# access_database requires the name of a sqlite3 database file and the query.
# It does not return the result of the query.
def access_database(dbfile, query, parameters=()):
    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    cursor.execute(query, parameters)
    connect.commit()
    connect.close()

# access_database requires the name of an sqlite3 database file and the query.
# It returns the result of the query
def access_database_with_result(dbfile, query, parameters=()):
    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    rows = cursor.execute(query, parameters).fetchall()
    connect.commit()
    connect.close()
    return rows



def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
       currently loaded page to be replaced."""
    return {"type":"refill","where":where,"what":what}


def build_response_redirect(where):
    """This function builds the page redirection action
       It indicates which page the client should fetch.
       If this action is used, only one instance of it should
       contained in the response and there should be no refill action."""
    return {"type":"redirect", "where":where}


def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""
    ## alter as required
    result = access_database_with_result("traffic.db", """SELECT COUNT (*) FROM session \
                                                                 WHERE userid=? AND magic=? AND end = 0""",
                                         (iuser, imagic))
    if list(result)[0][0] == 1:
        return True
    else:
        return False


def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    endtime = int(time.time())
    access_database("traffic.db",
                    """UPDATE session SET end=? WHERE userid=? AND magic=? AND end = 0""",
                    (endtime, iuser, imagic))
    #return

def handle_login_request(iuser, imagic, parameters):
    """A user has supplied a username (parameters['usernameinput'][0])
       and password (parameters['passwordinput'][0]) check if these are
       valid and if so, create a suitable session record in the database
       with a random magic identifier that is returned.
       Return the username, magic identifier and the response action set."""
    if handle_validate(iuser, imagic) == True:
    # the user is already logged in, so end the existing session.
        handle_delete_session(iuser, imagic)

    response = []
## alter as required
    if 'usernameinput' and 'passwordinput' in parameters:

        access_database("traffic.db",
                        """DELETE FROM session \
                        WHERE sessionid=? AND magic=?""",
                        (0, 330362070415))

        crosscheck = access_database_with_result("traffic.db",
                                                """SELECT * FROM users \
                                                WHERE username=? AND password=?""",
                                                (parameters['usernameinput'][0], parameters['passwordinput'][0]))
        if len(crosscheck) == 1:
            result = access_database_with_result('traffic.db',
                                                """SELECT * FROM session \
                                                WHERE userid=? AND end = 0""",
                                                (crosscheck[0][0], ))
            if len(result) == 1:
                response.append(build_response_refill('message', 'User Is Already Logged In'))
                user = '!'
                magic = ''
            else:
                user = crosscheck[0][0]
                magic = int(str(uuid.uuid4().int)[:12])
                access_database("traffic.db",
                                """INSERT INTO session (magic, userid, start, end) \
                                VALUES(?, ?, ?, ?)""",
                                (magic, user, int(time.time()), 0))
                response.append(build_response_redirect('/page.html'))
                response.append(build_response_refill('total', '0'))
        else:
            response.append(build_response_refill('message', 'Invalid password'))
            user = '!'
            magic = ''
    else:
        response.append(build_response_refill('message', 'Invalid Login Details '))
        user = '!'
        magic = ''

#if parameters['usernameinput'][0] == 'test': ## The user is valid
##response.append(build_response_redirect('/page.html'))
#user = 'test'
#magic = '1234567890'
#else: ## The user is not valid
#response.append(build_response_refill('message', 'Invalid password'))
#user = '!'
#magic = ''
    return [user, magic, response]
    #else:
        #response.append(build_response_refill('message', 'Invalid Login Details '))
        ##user = '!'
        #magic = ''

    #if parameters['usernameinput'][0] == 'test': ## The user is valid
        ##response.append(build_response_redirect('/page.html'))
        #user = 'test'
        #magic = '1234567890'
    #else: ## The user is not valid
        #response.append(build_response_refill('message', 'Invalid password'))
        #user = '!'
        #magic = ''


def unique_id(iuser, imagic):
    id = access_database_with_result('traffic.db', \
                                     """SELECT sessionid FROM session \
                                     INNER JOIN users u on session.userid = u.userid \
                                     WHERE session.userid=? AND magic=?""",
                                     (iuser,imagic))
    return id #inner join on users

def handle_add_request(iuser, imagic, parameters):
    """The user has requested a vehicle be added to the count
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
        user = ''
        magic = ''
    else: # 'locationinput' not in parameters: (token equivalent to sessionid)
        ## a valid session so process the addition of the entry.
        user = str(unique_id(iuser, imagic)[0][0])
        magic = imagic
        #sessionid from session (iuser,imagic)

        if 'locationinput' not in parameters:
            response.append(build_response_refill('message', 'Entry Cannot Be Empty; Please Enter Valid Location.'))
        else:
            types=['car', 'taxi', 'bus', 'bicycle', 'motorbike', 'van', 'truck', 'other']
            occupancy = str(list(range(1,5)))
            if parameters['typeinput'][0] in types and parameters['occupancyinput'][0] in occupancy:
                response.append(build_response_refill('message', 'Entry added.'))
                access_database("traffic.db",
                                """INSERT INTO traffic (sessionid, time, type, occupancy, location, mode) \
                                VALUES(?, ?, ?, ?, ?, ?)""",
                                (user, int(time.time()), parameters['typeinput'][0], parameters['occupancyinput'][0], parameters['locationinput'][0], 1))
                count = access_database_with_result("traffic.db",
                                                    """SELECT COUNT (*) FROM traffic \
                                                    WHERE sessionid=? AND mode = 1""",
                                                    (user, ))
                response.append(build_response_refill('total', str(count[0][0])))
            else:
                response.append(build_response_refill('message', 'Invalid Input'))
                response.append(build_response_refill('total', '0'))

        #response.append(build_response_refill('message', 'Entry added.'))
        #response.append(build_response_refill('total', '0'))
    user = ''
    magic = ''
    return [user, magic, response]




def handle_undo_request(iuser, imagic, parameters):
    """The user has requested a vehicle be removed from the count
       This is intended to allow counters to correct errors.
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
        user = ''
        magic = ''
    else: # 'locationinput' not in parameters: (token equivalent to sessionid)
        ## a valid session so process the addition of the entry.
        user = str(unique_id(iuser, imagic)[0][0])
        magic = imagic

        if 'locationinput' not in parameters:
            response.append(build_response_refill('message', 'Entry Cannot Be Empty; Please Enter Valid Location.'))
        else:
            occupancy = str(list(range(1,5)))
            types=['car', 'taxi', 'bus', 'bicycle', 'motorbike', 'van', 'truck', 'other']
            if parameters['typeinput'][0] in types and parameters['occupancyinput'][0] in occupancy:
                matches = access_database_with_result("traffic.db",
                                                      """SELECT MAX(recordid) FROM traffic WHERE \
                                                      sessionid=? AND type=? AND occupancy=? \
                                                      AND location=? AND mode=1""",
                                                      (user, parameters['typeinput'][0], parameters['occupancyinput'][0], parameters['locationinput'][0]))
                if matches[0][0] == None:
                    response.append(build_response_refill('message', 'No Matching Entries Found'))

                else:
                    access_database("traffic.db",
                                    """UPDATE traffic SET mode = 2 \
                                    WHERE recordid=(SELECT MAX(recordid) FROM traffic WHERE \
                                    sessionid=? AND type=? AND occupancy=? \
                                    AND location=? AND mode=1)""",
                                    (user, parameters['typeinput'][0], parameters['occupancyinput'][0], parameters['locationinput'][0]))
                    access_database("traffic.db",
                                    """INSERT INTO traffic (sessionid, time, type, occupancy, location, mode) \
                                    VALUES(?, ?, ?, ?, ?, ?)""",
                                    (user, int(time.time()), parameters['typeinput'][0], parameters['occupancyinput'][0], parameters['locationinput'][0], 0))
                    response.append(build_response_refill('message', 'Entry Un-done.'))
                #else:
                #response.append(build_response_refill('message', 'No Matching Entries Found'))

                    count = access_database_with_result("traffic.db",
                                                        """SELECT COUNT (*) FROM traffic \
                                                        WHERE sessionid=? AND mode = 1""",
                                                        (user, ))
                    response.append(build_response_refill('total', str(count[0][0])))
            else:
                response.append(build_response_refill('message', 'Occupancy To Be Undone Out Of Range'))
                #response.append(build_response_refill('total', str(count[0][0])))





        ##respone.append(build_response_refill('message', 'No Matching Entries Found'))
        #else:

        ##response.append(build_response_refill('message', 'Entry Un-done.'))
        #response.append(build_response_refill('total', '0'))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_back_request(iuser, imagic, parameters):
    """This code handles the selection of the back button on the record form (page.html)
       You will only need to modify this code if you make changes elsewhere that break its behaviour"""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
    else:
        response.append(build_response_redirect('/summary.html'))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_logout_request(iuser, imagic, parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
       You will need to ensure the end of the session is recorded in the database
       And that the session magic is revoked."""

    endtime = int(time.time())
    access_database("traffic.db", """UPDATE session SET end=? WHERE userid=? AND magic=?""", (endtime, iuser, imagic))
    response = []
    ## alter as required
    response.append(build_response_redirect('/index.html'))
    user = '!'
    magic = ''
    return [user, magic, response]


def handle_summary_request(iuser, imagic, parameters):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    get_id = str(unique_id(iuser, imagic)[0][0])
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
    else:

        sum_car = access_database_with_result("traffic.db",
                                              """SELECT COUNT (*) FROM traffic \
                                              WHERE sessionid=? AND type=? AND mode=?""",
                                              (get_id , 'car', 1))
        sum_taxi = access_database_with_result("traffic.db",
                                               """SELECT COUNT (*) FROM traffic \
                                               WHERE sessionid=? AND type=? AND mode=?""",
                                               (get_id , 'taxi', 1))
        sum_bus = access_database_with_result("traffic.db",
                                              """SELECT COUNT (*) FROM traffic \
                                              WHERE sessionid=? AND type=? AND mode=?""",
                                              (get_id , 'bus', 1))
        sum_motorbike = access_database_with_result("traffic.db",
                                                    """SELECT COUNT (*) FROM traffic \
                                                    WHERE sessionid=? AND type=? AND mode=?""",
                                                    (get_id , 'motorbike', 1))
        sum_bicycle = access_database_with_result("traffic.db",
                                                  """SELECT COUNT (*) FROM traffic \
                                                  WHERE sessionid=? AND type=? AND mode=?""",
                                                  (get_id , 'bicycle', 1))
        sum_van = access_database_with_result("traffic.db",
                                              """SELECT COUNT (*) FROM traffic \
                                              WHERE sessionid=? AND type=? AND mode=?""",
                                              (get_id , 'van', 1))
        sum_truck = access_database_with_result("traffic.db",
                                                """SELECT COUNT (*) FROM traffic \
                                                WHERE sessionid=? AND type=? AND mode=?""",
                                                (get_id , 'truck', 1))
        sum_other = access_database_with_result("traffic.db",
                                                """SELECT COUNT (*) FROM traffic \
                                                WHERE sessionid=? AND type=? AND mode=?""",
                                                (get_id , 'other', 1))
        sum_total = access_database_with_result("traffic.db",
                                                """SELECT COUNT (*) FROM traffic \
                                                WHERE sessionid=? AND mode=?""",
                                                (get_id , 1))

        response.append(build_response_refill('sum_car', str(sum_car[0][0])))
        response.append(build_response_refill('sum_taxi', str(sum_taxi[0][0])))
        response.append(build_response_refill('sum_bus', str(sum_bus[0][0])))
        response.append(build_response_refill('sum_motorbike', str(sum_motorbike[0][0])))
        response.append(build_response_refill('sum_bicycle', str(sum_bicycle[0][0])))
        response.append(build_response_refill('sum_van', str(sum_van[0][0])))
        response.append(build_response_refill('sum_truck', str(sum_truck[0][0])))
        response.append(build_response_refill('sum_other', str(sum_other[0][0])))
        response.append(build_response_refill('total', str(sum_total[0][0])))
        user = ''
        magic = ''
    return [user, magic, response]

#def export_offline_summary


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, response] = handle_back_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(build_response_refill('message', 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                response = []
                response.append(build_response_refill('message', 'Internal Error: Command not found.'))

            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))

        elif self.path.endswith('/statistics/hours.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for /statistics/hours.csv should be handled.
            ## you should check a valid user is logged in. You are encouraged to wrap this behavour in a function.
            text = "Username,Day,Week,Month\n"
            response =[]
            if handle_validate(user_magic[0], user_magic[1]) != True:
                #Invalid sessions redirect to login
                response.append(build_response_redirect('/index.html'))
            else:
                db = sqlite3.connect("traffic.db")
                cursor = db.cursor()
                cursor.execute("""SELECT MAX(strftime('%s', datetime(end, 'unixepoch', 'localtime'))) \
                 FROM session WHERE end>?""",(0, ))
                recent_logout = cursor.fetchone()
                #print(recent_logout)
                cursor.execute("""SELECT MAX(strftime('%s', datetime(start, 'unixepoch', 'localtime'),'start of day')) \
                FROM session WHERE end>?""",(0, ))
                recent_date = cursor.fetchone()
                #print(recent_date)
                recent_week = int(recent_date[0]) - 604800
                #print(recent_week)
                cursor.execute("""SELECT MAX(strftime('%s', datetime(start, 'unixepoch', 'localtime'),'start of month')) \
                FROM session WHERE end>?""",(0, ))
                recent_month = cursor.fetchone()
                #print(recent_month)

                day_info = access_database_with_result("traffic.db",
                                                       """SELECT users.username, SUM(SESSION.end-SESSION.start) FROM users \
                                                       INNER JOIN session WHERE USERS.userid=session.userid AND end <=? AND start>=? \
                                                       group by users.username""",(int(recent_logout[0]),int(recent_date[0])))
                week_info = access_database_with_result("traffic.db",
                                                        """SELECT users.username, SUM(SESSION.end-SESSION.start) FROM users \
                                                        INNER JOIN session WHERE USERS.userid=session.userid AND end <=? AND start>=? \
                                                        group by users.username""",(int(recent_logout[0]),recent_week))
                month_info = access_database_with_result("traffic.db",
                                                        """SELECT users.username, SUM(SESSION.end-SESSION.start) FROM users \
                                                        INNER JOIN session WHERE USERS.userid=session.userid AND end <=? AND start>=? \
                                                        group by users.username""",(int(recent_logout[0]),int(recent_month[0])))




                for record in day_info:
                    text+=(record[0]+'\n')
                    text+=(str(ceil((record[1] * 24) * 10) / 10)+'\n')
                for record in week_info:
                    text+=(str(ceil((record[1] * 24) * 10) / 10)+'\n')
                for record in month_info:
                    text+=(str(ceil((record[1] * 24) * 10) / 10)+'\n')





            #text += "test1,0.0,0.0,0.0\n" # not real data
            #text += "test2,0.0,0.0,0.0\n"
            #text += "test3,0.0,0.0,0.0\n"
            #text += "test4,0.0,0.0,0.0\n"
            #text += "test5,0.0,0.0,0.0\n"
            #text += "test6,0.0,0.0,0.0\n"
            #text += "test7,0.0,0.0,0.0\n"
            #text += "test8,0.0,0.0,0.0\n"
            #text += "test9,0.0,0.0,0.0\n"
            #text += "test10,0.0,0.0,0.0\n"
            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('hours.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        elif self.path.endswith('/statistics/traffic.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for  /statistics/traffic.csv should be handled.
            ## you should check a valid user is checked in. You are encouraged to wrap this behavour in a function.
            response = []
            #text = "This should be the content of the csv file."
            text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
            #text += '"Main Road",car,0,0,0,0\n' # not real data
            if handle_validate(user_magic[0], user_magic[1]) != True:
                #Invalid sessions redirect to login
                response.append(build_response_redirect('/index.html'))
                #user = ''
                #magic = ''
            else:
                types = ['car', 'taxi', 'bus', 'bicycle', 'motorbike', 'van', 'truck', 'other']
                #headers = ['Location','Type','Occupancy1','Occupancy2','Occupancy3','Occupancy4']
            #text += "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
            #text += '"Main Road",car,0,0,0,0\n' # not real data
                db = sqlite3.connect("traffic.db")
                cursor = db.cursor()
                cursor.execute("""SELECT MAX(strftime('%s', datetime(time, 'unixepoch', 'localtime'),'start of day')) \
                FROM traffic WHERE mode=?""",(1, ))
                recent_date = cursor.fetchone()
            #print(recent_date[0])
                ####records = access_database("traffic.db",
                                        ###"""SELECT location, type, occupancy, COUNT(occupancy) \
                                        ##FROM traffic WHERE mode=? AND time>=? GROUP BY type, occupancy;""",
                                        #(1, int(recent_date[0])))
                for vehicle_types in types:
                    records = list(cursor.execute("""SELECT location, type, \
                    CAST(SUM(occupancy = 1) AS TEXT) as count_1, \
                    CAST(SUM(occupancy = 2) AS TEXT) as count_2, \
                    CAST(SUM(occupancy = 3) AS TEXT) as count_3, \
                    CAST(SUM(occupancy = 4) AS TEXT) as count_4 \
                    FROM traffic WHERE mode=? AND type=? AND time>=? GROUP BY type;""",
                                                (1, vehicle_types, int(recent_date[0]))))
                    recording = list(itertools.chain(*records))
                    inputs = ','.join(recording)
                    #final_text = ','.join(inputs)
                    #print(text)
                    #print(inputs)


                    if inputs:
                        text+=(inputs+'\n')
                    ###print(text)
                    #text = '\n'.join(text)
                        #text+=(records[0][1])
                        ####text+=(str(records[0][2]))
                        ###text+=(str(records[0][3]))
                        ##text+=(str(records[0][4]))
                        #text+=(str(records[0][5]))


                    #data=np.array(text)

                    #df = pd.DataFrame(data, columns=headers)
                    #df
                    #df.to_csv('traffic.csv')


                # /Users/zoe/opt/anaconda3/bin/python "/Users/zoe/labs/traffic app/traffic app code/og_server.py" 8081

                encoded = bytes(text, 'utf-8')
            ####with open ('traffic.csv', 'a+', newline='') as f:
                ###for record in text:
                    ##write = csv.writer(f)
                    #write.writerow(record)
                #with open('traffic.csv', 'w', newline='', encoding='utf-8') as f:
                    ####csv_out=csv.writer(f, dialect='excel')
                    ###csv_out.writerow(['Location','Type','Occupancy1','Occupancy2','Occupancy3','Occupancy4'])
                    ##for record in text:
                        #csv_out.writerow(record)
                self.send_response(200)
                self.send_header('Content-type', 'text/csv')
                self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('traffic.csv'))
                self.send_header("Content-Length", len(encoded))
                self.end_headers()
                self.wfile.write(encoded)

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if(len(sys.argv)<2): # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return till the server is aborted.

run()
#/usr/local/bin/python3.9 "/Users/zoe/Downloads/code 3/og_server.py" 8081
