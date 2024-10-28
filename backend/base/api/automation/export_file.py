from office365.sharepoint.client_context import ClientContext
import os
import mysql.connector 
import pandas as pd 
import numpy as np
from base.models import *
from base.api.serializers import * 
import re
import datetime
from datetime import timedelta
from urllib.parse import urlparse

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import json
import traceback


def log_to_file(filename, userid, message):
    log_message = f"{datetime.datetime.now()} - UserID: {userid} - {message}\n"
    file_exists = os.path.isfile(filename)
    with open(filename, 'a') as file:
        file.write(log_message)
    
    if not file_exists:
        print(f"File '{filename}' created and log entry added.")
    else:
        print(f"Log entry added to '{filename}'.")


def process_decrypted_data(decrypted_data):
    try:
        decrypted_string = decrypted_data.decode('utf-8')

        dectdata = json.loads(decrypted_string)
        return dectdata

    except UnicodeDecodeError as e:
        print(f"Unicode decode error: {e}")
        print(f"Raw decrypted data: {decrypted_data}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return None

def decrypt_string(encrypted_string, secret_key):
    encrypted_data = base64.b64decode(encrypted_string)
    secret_key = secret_key.encode('utf-8').ljust(32, b'\0')[:32]

    # Extract the IV (first 16 bytes) and ciphertext (rest)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)


    # cipher = AES.new(secret_key, AES.MODE_ECB)
    # decrypt_data = cipher.decrypt(encrypted_data)
    dectdata = process_decrypted_data(decrypted_data)
    # decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    # decrypted_string = decrypt_data.decode('utf-8')
    # dectdata = json.loads(decrypted_string)
    return dectdata

def is_json_string(string):
    try:
        json.loads(string)
        return True
    except ValueError:
        return False

def remove_spec_char(string):
    bad_chars = [';', ':', '!', "*", "-", '/', '@', "&", " "]
    string = string.replace("-", '')
    for i in bad_chars:
        test_string = string.replace(i, '')
    return str(test_string)

def count(data, name, condition='', month='', dateval='', all='false', year='', base_key='', base_value=''):
    count = 0
    if base_key != '' and base_value != '':
        for pindex, sheet in data.iterrows():
            # if sheet[name] != None and sheet[dateval] != None and sheet[name].strip() in condition and int(sheet[dateval].strftime("%m")) == month and sheet[dateval].strftime("%Y") == str(datetime.date.today().year-1):
            if sheet[name] != None and sheet[dateval] != None and sheet[base_key] in base_value and sheet[name].strip() in condition and int(sheet[dateval].strftime("%m")) == month and sheet[dateval].strftime("%Y") == str(year):
                count += 1
    elif all == 'false' and condition != '' and month != '':
        for pindex, sheet in data.iterrows():
            # if sheet[name] != None and sheet[dateval] != None and sheet[name].strip() in condition and int(sheet[dateval].strftime("%m")) == month and sheet[dateval].strftime("%Y") == str(datetime.date.today().year-1):
            if sheet[name] != None and sheet[dateval] != None and sheet[name].strip() in condition and int(sheet[dateval].strftime("%m")) == month and sheet[dateval].strftime("%Y") == str(year):
                count += 1
    elif condition == '':
        for pindex, sheet in data.iterrows():
            if sheet[dateval] != None and int(sheet[dateval].strftime("%m")) == month and sheet[dateval].strftime("%Y") == str(year):
                count += 1
    elif month == '':
        for pindex, sheet in data.iterrows():
            if sheet[name] != None and sheet[name].strip() in condition:
                count += 1
    else:
        for pindex, sheet in data.drop_duplicates().iterrows():
            if sheet[name] != None and eval(condition) and int(sheet[dateval].strftime("%m")) == month and sheet[dateval].strftime("%Y") == str(year):
                count += 1
    return count

def c_count(c_data, condition, month, dateval):
    count = 0
    for pindex, c_sheet in c_data.iterrows():
        if c_sheet[dateval] != None and eval(condition) and int(c_sheet[dateval].strftime("%m")) == month and c_sheet[dateval].strftime("%Y") == str(datetime.date.today().year-1):
            count += 1
    return int(count)

def Tosum(data, name, month_col, month, year, base_key='', base_value=''):
    sumVal = 0
    if base_key != '' and base_value != '':
        for pindex, sheet in data.iterrows():
            if sheet[name] != None and sheet[base_key] == base_value and int(sheet[month_col].strftime("%m")) == month and sheet[month_col].strftime("%Y") == str(year):
                sumVal += sheet[name]
    else:
        for pindex, sheet in data.iterrows():
            if sheet[name] != None and int(sheet[month_col].strftime("%m")) == month and sheet[month_col].strftime("%Y") == str(year):
                sumVal += sheet[name]
    return sumVal

def extract_sheet_names(expression):
    # Regular expression to find sheet names with more flexibility
    # Matches names with alphanumeric characters, underscores, spaces, and handles different brackets
    pattern = r'(\w[\w\s]*?)\[\w[\w\s]*?\]'
    # Find all matches in the expression
    sheet_names = re.findall(pattern, expression)
    # Remove duplicates and return
    unique_sheet_names = list(set(sheet_names))
    return unique_sheet_names

def filtering_on_condition(data, filter_condition):
    pattern = re.compile(r'(\w+)(==|!=|>=|<=|>|<)(.+)')
    match = pattern.match(filter_condition)
    filtered_df = data
    if match:
        column, op, value = match.groups()
        value = value.strip('"')  # Remove quotes from the value

        if op == '==':
            filtered_df = data[data[column] == value]
        elif op == '!=':
            filtered_df = data[data[column] != value]
        elif op == '>':
            filtered_df = data[data[column] > float(value)]
        elif op == '<':
            filtered_df = data[data[column] < float(value)]
        elif op == '>=':
            filtered_df = data[data[column] >= float(value)]
        elif op == '<=':
            filtered_df = data[data[column] <= float(value)]

    return filtered_df

def calculate_avg(values):
    return sum(values) / len(values) if values else 0

def calculate_sum(values):
    return sum(values)

def calculate_count(values, condition=None):
    if condition:
        return sum(1 for v in values if eval(f"v {condition}"))
    return len(values)

def evaluate_expression(expression, sheet_data):
    # Regular expression to find function calls like count(sheet1[cell1] != 'N')
    func_pattern = re.compile(r'(\w*)\((\w+)\[(\w+)\](?:\s*([!=<>]+)\s*\'?([\w\d\s]+)\'?)?\)')
    
    def replace_func(match):
        func_name, sheet_name, cell_name, operator, condition_value = match.groups()
        func_name = func_name.lower()
        values = sheet_data.get(cell_name, [])
        
        if operator and condition_value:
            condition = f"{operator} {repr(condition_value)}"
        else:
            condition = None
        
        if not func_name:
            func_name = 'avg'
        
        if func_name == 'avg':
            return str(calculate_avg(values))
        elif func_name == 'sum':
            return str(calculate_sum(values))
        elif func_name == 'count':
            return str(calculate_count(values, condition))
        else:
            return f"Error: Unknown function {func_name}"

    # Replace function calls with their computed values
    while func_pattern.search(expression):
        expression = func_pattern.sub(replace_func, expression)

    # Regular expression to find sheet[cell] patterns without a function
    sheet_pattern = re.compile(r'(\w+)\[(\w+)\]')

    def replace_sheet(match):
        sheet_name, cell_name = match.groups()
        values = sheet_data.get(cell_name, [])
        return str(values)
    
    # Apply avg to any sheet[cell] patterns  
    expression = sheet_pattern.sub(replace_sheet, expression)
    
    # Replace textual operations with mathematical symbols
    replacements = {
        r'\bdivided by\b': '/',
        r'\bmultiply by\b': '*',
        r'\bplus\b': '+',
        r'\bminus\b': '-',
    }

    for word, symbol in replacements.items():
        expression = re.sub(word, symbol, expression, flags=re.IGNORECASE)
    
    # Remove any extra spaces
    expression = re.sub(r'\s+', '', expression)
    

    # Evaluate the expression safely
    try:
        result = eval(expression)
    except Exception as e:
        return f"Error evaluating expression: {e}"
    
    return result




def split_url(url):
    parse_object = urlparse(url)
    path_segments = parse_object.path.split('/')
    base_name = f"{parse_object.scheme}://{parse_object.netloc}/"
    
    # If there are at least 3 segments, combine the first three
    if len(path_segments) > 2:
        base_name += "/".join(path_segments[1:3]) + '/'
        remainder_path = "/".join(path_segments[3:])
    else:
        remainder_path = "/".join(path_segments[1:])
        

    fileExtension = remainder_path.split(".")[-1]
    
    return base_name, remainder_path, fileExtension

def automationKpiActuals():
    log_filename = 'logfile.txt'
    user_id = '1'
    months = [1,2,3,4,5,6,7,8,9,10,11,12]
    computation_data_list = computation_details.objects.filter(delete_flag="N").values('id','kpi_id', 'url', 'sheet1', 'sheet2', 'user_name', 'Password', 'filter_condition', 'computation_logic', 'period_column', 'Computation_type', 'created_date','created_by','last_updated_by')
    for computation_data in computation_data_list:
        years = []
        kpi_data_list = kpi_details.objects.filter(delete_flag="N", id= computation_data['kpi_id']).values('id','created_date','created_by','last_updated_by','objective_id','scorecard_details_id','scorecard_id')
        del_data = kpi_actuals.objects.filter(kpi_id=computation_data['kpi_id']).delete()
        
        try:
            if computation_data['Computation_type'] == 'N':
                scorecard_data = scorecard.objects.filter(delete_flag="N", id=kpi_data_list[0]['scorecard_id']).values("from_date","to_date")
                for y in range(int(scorecard_data[0]['from_date'].strftime("%Y")), int(scorecard_data[0]['to_date'].strftime("%Y"))+1):
                    years.append(y)
                Rooturl, server_relative_url, fileExtension = split_url(computation_data['url'])
                script_dir = os.path.dirname(os.path.abspath(__file__))
                file_path = os.path.join(script_dir, "..","file_warehouse", "shared_file.xlsx")

                # Decryptpassword = decrypt_string(computation_data['Password'], "Cittabase@XkhZG4fW2t2WJ$Cshlkb7V")
                # print(f"==>> computation_data['Password']: {computation_data['Password']}")
                # print(f"==>> Decryptpassword: {Decryptpassword}")

            
                sheet_names = extract_sheet_names(computation_data['computation_logic'])

                ctx = ClientContext(Rooturl).with_user_credentials(computation_data['user_name'], computation_data['Password'])
                with open(file_path, "wb") as local_file:
                    file = ctx.web.get_file_by_server_relative_url(server_relative_url)
                    if file is None:
                        raise ValueError(f"File not found at {server_relative_url}")
                    file.download(local_file)
                    ctx.execute_query()
                    # ---==== Get specific sheet in excel ===---
                    xls = pd.ExcelFile(local_file.name)
                    sheet_data = pd.read_excel(xls, sheet_names[0])
                    Condition = computation_data['filter_condition']
                    filtered_data = filtering_on_condition(sheet_data, Condition)

                    for year in years:
                        for month in months:
                            # filtered_data[computation_data['period_column']] = pd.to_datetime(filtered_data[computation_data['period_column']], errors='coerce')
                            # filtered_data.loc[:, computation_data['period_column']] = pd.to_datetime(filtered_data[computation_data['period_column']], errors='coerce')
                            filtered_data.loc[:, computation_data['period_column']] = pd.to_datetime(
                                filtered_data.loc[:, computation_data['period_column']], 
                                errors='coerce'
                            )
                            period_filterd_data = filtered_data.loc[filtered_data[computation_data['period_column']].dt.month == int(month)]
                            # period_filterd_data = period_filterd_data[period_filterd_data[computation_data['period_column'].dt.year == int(year)]]

                            actuals_data = evaluate_expression(computation_data['computation_logic'], period_filterd_data)
                            actuals_value = int(round(float(actuals_data)))

                            kpi_actual_data = {
                                "scorecard_id": kpi_data_list[0]['scorecard_id'],
                                "perspective_id": kpi_data_list[0]['scorecard_details_id'],
                                "objective_id": kpi_data_list[0]['objective_id'],
                                "kpi_id": kpi_data_list[0]['id'],
                                "period": pd.to_datetime(period_filterd_data[computation_data['period_column']].iloc[0]).date(),
                                "delete_flag": 'N',
                                "actuals": actuals_value,
                                "created_by": kpi_data_list[0]["created_by"],
                                "last_updated_by": kpi_data_list[0]["last_updated_by"],
                            } 
                            actuals_serializer = kpi_actuals_serializer(data=kpi_actual_data)
                            if actuals_serializer.is_valid():
                                actuals_serializer.save()

                            else:
                                print(actuals_serializer.errors)           
                    
        except Exception as exce:
            log_to_file(log_filename, user_id, f"Exception raised: {exce}")

    log_to_file(log_filename, user_id, "Scheduler completed successfully")
    print("Actuals Process Has been completed")