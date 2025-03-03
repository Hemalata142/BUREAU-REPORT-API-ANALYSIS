import paramiko
import datetime
import requests
import json 
import psycopg2
import os
import sys
import pandas as pd 
from thefuzz import fuzz
from random import randint
import math
import random
import codecs
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import boto3
import os
from stat import S_ISDIR, S_ISREG
from datetime import date
import dateutil.relativedelta
from dateutil.relativedelta import relativedelta


def generate_random_hex(byte_length: int) -> str:
    string_length = byte_length * 2
    alphabet = "abcdef0123456789"
    s = ""

    for i in range(string_length):
        r = int(math.floor(random.random() * len(alphabet)))
        s += alphabet[r]

    # prevent null block.
    s = s.replace("00", "11")
    return s


def _data_from_hex_string(hex_string: str) -> bytes:
    hex_string = hex_string.strip().replace(' ', '').lower()
    alphabet = "abcdef0123456789"

    for ch in hex_string:
        if ch not in alphabet:
            raise Exception('Invalid encryption hex data')

    data_bytes = codecs.decode(hex_string, 'hex')
    return data_bytes


def data_to_hex_string(data_bytes: bytes) -> str:
    hex_string = codecs.encode(data_bytes, 'hex').decode()
    return hex_string


def encrypt_data(plain_text: str, hex_key: str) -> str:
    _check_key(hex_key)

    # generate random IV (16 bytes)
    hex_iv = generate_random_hex(16)

    # convert plainText to hex string.
    bytes_data = plain_text.encode('utf-8')
    hex_str = data_to_hex_string(bytes_data)

    cipher_hex_str = _encrypt_data(hex_str, hex_key, hex_iv)

    hmac_hex_key = generate_random_hex(16)
    hmac_hex_str = _compute_HMAC(hex_iv, cipher_hex_str, hex_key, hmac_hex_key)

    encrypted_hex_str = hex_iv + hmac_hex_key + hmac_hex_str + cipher_hex_str
    return encrypted_hex_str


def decrypt_data(hex_str: str, hex_key: str) -> str:
    _check_key(hex_key)

    plain_text = None
    if len(hex_str) > 128:
        hex_iv = hex_str[:32]
        hmac_hex_key = hex_str[32:64]
        hmac_hex_str = hex_str[64:128]
        cipher_hex_str = hex_str[128:]

        computed_hmac_hex_str = _compute_HMAC(hex_iv, cipher_hex_str, hex_key, hmac_hex_key)
        if computed_hmac_hex_str.lower() == hmac_hex_str.lower():
            decrypted_str = _decrypt_data(cipher_hex_str, hex_key, hex_iv)
            data = _data_from_hex_string(decrypted_str)
            plain_text = data.decode('utf-8')

    return plain_text


def _compute_HMAC(hex_iv: str, cipher_hex: str, hex_key: str, hmac_hex_key: str):
    hex_key = hex_key.strip().replace(' ', '').lower()
    hmac_hex_key = hmac_hex_key.lower()

    hex_str = hex_iv + cipher_hex + hex_key
    hex_str = hex_str.lower()

    data = hex_str.encode('utf-8')
    hmac_key = hmac_hex_key.encode('utf-8')

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(data)
    hash_bytes = hmac.digest()

    hash_hex_str = data_to_hex_string(hash_bytes)
    return hash_hex_str


def _check_key(hex_key: str):
    hex_key = hex_key.strip().replace(' ', '').lower()

    if len(hex_key) != 64:
        raise Exception("key length is not 256 bit (64 hex characters)")

    key_len = len(hex_key)
    i = 0
    while i < key_len:
        if hex_key[i] == '0' and hex_key[i+1] == '0':
            raise Exception("key cannot contain zero byte block")

        i += 2


def _encrypt_data(hex_string: str, hex_key: str, hex_iv: str) -> str:
    data = _data_from_hex_string(hex_string)
    key = _data_from_hex_string(hex_key)
    iv = _data_from_hex_string(hex_iv)

    # PyCrypto does not have PKCS7 Padding alforithm, I have to implement on my own.
    #
    # Note: if plain_text length is multiple of 16,
    #        then a sequence of value chr(BS) in length 16 will be appended to the origin data
    data = data + (chr(16 - len(data) % 16) * (16 - len(data) % 16)).encode('utf-8')

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(data)
    encrypted_hex_data = data_to_hex_string(encrypted_data)
    return encrypted_hex_data


def _decrypt_data(hex_string: str, hex_key: str, hex_iv: str) -> str:
    data = _data_from_hex_string(hex_string)
    key = _data_from_hex_string(hex_key)
    iv = _data_from_hex_string(hex_iv)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(data)

    # PyCrypto does not have PKCS7 Padding alforithm, I have
    #   to implement un-pad on my own.
    decrypted_data = decrypted_data[:-ord(decrypted_data[len(decrypted_data) - 1:])]

    decrypted_hex_data = data_to_hex_string(decrypted_data)
    return decrypted_hex_data


current_date_time = datetime.datetime.now()
current_date_time = current_date_time.strftime("%Y_%m_%d_%H_%M_%S")

current_time = datetime.datetime.now()

# Credentials and Paths for SFTP
host = 'sftp.randomapps.com'
port = 1234
username = 'sftp_username'
password = 'sftp_password'
remote_file_path = "/path/to/Input_Files"
processed_file_path = "/path/to/Processed_Files"
output_file_path = "/path/to/Output_Files"

# This is a AWS RDS Postgresql Database CREDENTAILS
DB_NAME = "db_name"
DB_USER = "db_username"
DB_PASS = "db_password"
DB_HOST = "db_host"
DB_PORT = "db_port"


# state master was present in the DB.
def get_state_master(state_name):
    try:
        conn = psycopg2.connect(database=DB_NAME,
                                user=DB_USER,
                                password=DB_PASS,
                                host=DB_HOST,
                                port=DB_PORT)
    except:
        print("Database connection Failed! Kindly Contact Admin")

    cur = conn.cursor()

    sql_query = f'''select * from "dummy".state_m where dmetaphone(state_id::text) = dmetaphone('{state_name}'::text)'''

    state_df_code = pd.read_sql(sql_query,conn)
    
    print(state_name)
    for index,row in state_df_code.iterrows():
        state_code = int(row[f"{state_df_code.columns[2]}"])

    conn.commit()
    conn.close()

    print(state_code)
    if len(str(state_code)) == 1:
        return f"0{state_code}"
    else:
        return state_code


gender_dict = {
        "Female" : 1,
        "Male" : 2,
        "Transgender" : 3
    }

def get_gender_code(gender):
    ratio_min = 0 
    gender_code = 0 

    for i in list(gender_dict.keys()):
        match_ratio = fuzz.ratio(gender, i)
        if match_ratio > ratio_min:
            ratio_min = match_ratio
            gender_code = gender_dict[i]
    
    return gender_code


address_type_dict = {
        "Permanent Address" : "01",
        "Residence Address" : "02",
        "Office Address" : "03",
        "Not Categorized" : "04",
        "Mortgage Property address" : "05" 
    }


def get_address_type_code(address_type):
    ratio_min = 0 
    address_type_code = "00"

    for i in list(address_type_dict.keys()):
        match_ratio = fuzz.ratio(address_type, i)
        if match_ratio > ratio_min:
            ratio_min = match_ratio
            address_type_code = address_type_dict[i]
    
    return address_type_code


residence_type_dict = {
        "Owned" : "01",
        "Rented" : "02"
    }

def get_residence_type_code(residence_type):
    ratio_min = 0 
    residence_type_code = "00"

    for i in list(residence_type_dict.keys()):
        match_ratio = fuzz.ratio(residence_type, i)
        if match_ratio > ratio_min:
            ratio_min = match_ratio
            residence_type_code = residence_type_dict[i]
    
    return residence_type_code

def get_random_id():
    id = randint(100000000000, 999999999999)
    return id


def api_call(encrypted_payload):
    
    # This is not the actual API url
    api_url = "https://transunionAPIcall/api/Cibil/GetConsumerData"

    headers = {
        'Content-Type': 'application/json',
    }
    
    try:
        encrypted_payload = {"EncryptedRequestString":f"{encrypted_payload}"}
        encrypted_payload = json.dumps(encrypted_payload)
        print(encrypted_payload)
        response = requests.request("POST", api_url, headers=headers, data=encrypted_payload)
        print("ResponseRaw",response)

        response = response.json()
        keys = list(response.keys()) 
        
        print("Response:",response[keys[0]])

        response = response[keys[0]]

        return response
    except Exception as e:
        return {
            'statusCode': 'ERROR:500',
            'body': json.dumps(f'Error: {str(e)}')
        }


def check_if_simple_dict(i):
    for key,value in i.items():
        if "list" in str(type(value)) or "value" in str(type(value)):
            return False
    return True


# To handle complex Json converted to Dictionary
def handle_comple_dictionary(column_name,update_simple_dict,data): 
    if "dict" in str(type(data)):
        for key,value in data.items():
            update_simple_dict = handle_comple_dictionary(key,update_simple_dict,value)
    elif "list" in str(type(data)):
        for i in data:
            if "dict" in str(type(i)):
                check_simple_dict = check_if_simple_dict(i)
                if not check_simple_dict:
                    update_simple_dict = handle_comple_dictionary(None,update_simple_dict,i)
                else:
                    if column_name not in list(update_simple_dict.keys()):
                        update_simple_dict[column_name] = []
                        update_simple_dict[column_name].append(i)
                    else:
                        update_simple_dict[column_name].append(i)
            elif "list" in str(type(data)):
                update_simple_dict = handle_comple_dictionary(None,update_simple_dict,i)
    elif "str" in str(type(data)):
        try:
            if data is None:
                update_simple_dict[column_name] = "null"
            else:
                update_simple_dict[column_name] = data
        except Exception as e:
            print(e)
            print(update_simple_dict)
    elif "bool" in str(type(data)):
        try:
            if data is None:
                update_simple_dict[column_name] = "null"
            else:
                update_simple_dict[column_name] = data
        except Exception as e:
            print(e)
            print(update_simple_dict)  
    else:
        try:
            if data is None:
                update_simple_dict[column_name] = "null"
            else:
                update_simple_dict[column_name] = data
        except Exception as e:
            print(e)
            print(update_simple_dict)
            
    return update_simple_dict
    
    
# Convert Json to a Dataframe    
def convert_json_to_df(decrypted_payload):
    print("Convert Json to DF Start")
    decrypted_payload = str(decrypted_payload)
    print("++++++++++++++++",decrypted_payload)
    cibil_dict = json.loads(decrypted_payload)

    simple_dict = {}
    update_simple_dict = handle_comple_dictionary(None,simple_dict,cibil_dict)
    
    print(update_simple_dict)
    
    result_df = pd.DataFrame()
    
    try:
        if update_simple_dict["names"] != 'null':
            ds = update_simple_dict["names"]
            names_df = pd.DataFrame(ds)
            result_df = pd.concat([result_df,names_df],axis=1,join='outer')
            del update_simple_dict["names"]
        else:
            pass
    except Exception as e :
        print("ERROR",e)
    
    if "'ids':" in str(update_simple_dict):
        del update_simple_dict["ids"]
    else:
        pass
    
    if "'employment':" in str(update_simple_dict):
        del update_simple_dict["employment"]
    else:
        pass
    
    if "'reasonCodes':" in str(update_simple_dict):
        del update_simple_dict["reasonCodes"]
    else:
        pass

    try:
        if update_simple_dict["telephones"] != 'null':
            ds = update_simple_dict["telephones"]
            tele_df = pd.DataFrame(ds)
            tele_df.rename(columns={'index': 'index_telephone'}, inplace=True)
            result_df = pd.concat([result_df,tele_df],axis=1,join='outer')
            del update_simple_dict["telephones"]
        else:
            pass
    except Exception as e :
        print("ERROR",e)

    try:
        if update_simple_dict["emails"] != 'null':
            ds = update_simple_dict["emails"]
            email_df = pd.DataFrame(ds)
            email_df.rename(columns={'index': 'index_email'}, inplace=True)
            result_df = pd.concat([result_df,email_df],axis=1,join='outer')
            del update_simple_dict["emails"]
        else:
            pass
    except Exception as e :
        print("ERROR",e)

    try:
        if update_simple_dict["scores"] != 'null':
            ds = update_simple_dict["scores"]
            scores_df = pd.DataFrame(ds)
            scores_df.rename(columns={'index': 'index_scores'}, inplace=True)
            result_df = pd.concat([result_df,scores_df],axis=1,join='outer')
            del update_simple_dict["scores"]
        else:
            pass
    except Exception as e :
        print("ERROR",e)

    try:
        if update_simple_dict["addresses"] != 'null':
            ds = update_simple_dict["addresses"]
            address_df = pd.DataFrame(ds)
            address_df.rename(columns={'index': 'index_addresses'}, inplace=True)
            result_df = pd.concat([result_df,address_df],axis=1,join='outer')
            del update_simple_dict["addresses"]
        else:
            pass
    except Exception as e :
        print("ERROR",e)

    try:
        if update_simple_dict["accounts"] != 'null':
            ds = update_simple_dict["accounts"]
            account_df = pd.DataFrame(ds)
            print(account_df)
            account_df.rename(columns={'index': 'index_accounts'}, inplace=True)
            result_df = pd.concat([result_df,account_df],axis=1,join='outer')
            del update_simple_dict["accounts"]
        else:
            pass
    except Exception as e :
        print("ERROR",e)

    try:
        if update_simple_dict["enquiries"] != 'null':
            ds = update_simple_dict["enquiries"]
            enquiry_df = pd.DataFrame(ds)
            enquiry_df.rename(columns={'index': 'index_enquiry'}, inplace=True)
            result_df = pd.concat([result_df,enquiry_df],axis=1,join='outer')
            del update_simple_dict["enquiries"]
        else:
            pass
    except Exception as e :
        print("ERROR",e)
    
    print(update_simple_dict)

    other_df = pd.DataFrame(update_simple_dict,index=[0])

    result_df = pd.concat([result_df,other_df],axis=1,join='outer')

    result_df = result_df.drop_duplicates()

    return result_df


def remove_duplicate_columns(df):
    # Identify all columns
    columns = df.columns
    
    # Create a set to track seen columns
    seen = set()

    index = 0 
    
    for col in columns:   
        # Check if the column name or data has already been seen
        if col not in seen:
            seen.add(col)
        else:
            try:
                df.rename(columns = {f'{col}':f'{col}_{index}'}, inplace = True)
            except Exception as e:
                print(e)
        index+=1
    
    # Return DataFrame with only the unique columns
    return df
 

def get_payment_history_data(temp_result_df):
    try:
        pd.options.display.float_format = '{:.0f}'.format
        temp_result_df = temp_result_df[["paymentHistory","paymentStartDate","paymentEndDate"]]

        print(temp_result_df[["paymentHistory","paymentStartDate","paymentEndDate"]])
        
        

        temp_result_df['paymentStartDate'] = pd.to_datetime(temp_result_df['paymentStartDate'], format='%d%m%Y') 
        temp_result_df['paymentEndDate'] =pd.to_datetime(temp_result_df['paymentEndDate'], format='%d%m%Y') 
        temp_result_df['paymentStartDate'] = temp_result_df['paymentStartDate'].dt.strftime('%B-%Y')
        temp_result_df['paymentEndDate'] = temp_result_df['paymentEndDate'].dt.strftime('%B-%Y')
        temp_result_df['paymentStartDate'] = pd.to_datetime(temp_result_df['paymentStartDate'],format='%B-%Y')
        temp_result_df['paymentEndDate'] = pd.to_datetime(temp_result_df['paymentEndDate'],format='%B-%Y')  
        temp_result_df['paymentHistory']= temp_result_df['paymentHistory'].astype(str)

        print(temp_result_df['paymentHistory'].dtypes)
        final_list = []

        for index,row in temp_result_df.iterrows():
            payment_history_string = str(row["paymentHistory"])
            payment_history_string_list = [payment_history_string[i:i+3] for i in range(0, len(payment_history_string), 3)]
            # print(payment_history_string_list)
            payment_start_date = row["paymentStartDate"]
            payment_end_date = row["paymentEndDate"]

            current_date = row["paymentStartDate"]
            # print("START DATE:",current_date)
            # print("END DATE :",payment_end_date)
            
            i = 0 
            
            index2 = index
            
            try:
                print(current_date,index,row["paymentStartDate"],payment_start_date)
                current_date = current_date + relativedelta(months=1)
                while i < len(payment_history_string_list):
                    current_date = current_date - relativedelta(months=1)
                    temp_list = []
                    try:
                        temp_list = [f"Account No {index2+1}",str(current_date)[0:10],payment_history_string_list[i]]
                        final_list.append(temp_list)
                        # print(temp_list)
                    except Exception as e:
                        print("INDEX OUT OF RANGE")
                    
                    i+=1
            except Exception as e:
                print(e)
                
            
        result_df = pd.DataFrame(final_list, 
                        columns = ['ACCOUNT NO' , 'MONTH' , 'DPD']) 
        
        result_df["MONTH"] =  pd.to_datetime(result_df['MONTH'], format='%Y-%m-%d') 
        result_df['MONTH'] = result_df['MONTH'].dt.strftime('%B-%Y')
    except Exception as e:
        result_df = None

    return result_df

def get_state_master_value(state_code):
    try:
        conn = psycopg2.connect(database=DB_NAME,
                                user=DB_USER,
                                password=DB_PASS,
                                host=DB_HOST,
                                port=DB_PORT)
    except:
        print("Database connection Failed! Kindly Contact Admin")

    cur = conn.cursor()

    sql_query = f"""select * from "dummy".state_m where bureau_value::int = '{state_code}' """

    state_df_code = pd.read_sql(sql_query,conn)

    print("STATE DF DEBUG",state_code)
    print(state_df_code)
    for index,row in state_df_code.iterrows():
        state_name = row[f"{state_df_code.columns[0]}"]

    conn.commit()
    conn.close()

    return state_name


def get_account_type(account_code):
    try:
        conn = psycopg2.connect(database=DB_NAME,
                                user=DB_USER,
                                password=DB_PASS,
                                host=DB_HOST,
                                port=DB_PORT)
    except:
        print("Database connection Failed! Kindly Contact Admin")

    cur = conn.cursor()

    sql_query = f"""select * from vendor_stg.cnsmr_account_type_bureau_master where bureau_value = '{account_code}' """

    account_df_code = pd.read_sql(sql_query,conn)
    
    count_rows = len(account_df_code.index)
    
    if count_rows == 0 :
        account_name = account_code
    else:
        for index,row in account_df_code.iterrows():
            if index == 0:
                account_name = row[f"{account_df_code.columns[0]}"]

    conn.commit()
    conn.close()

    return account_name


def convert_codes_to_value(df):
    gender_master = {
        "Female" : 1,
        "Male" : 2,
        "Transgender" : 3
    }

    gender_dict_rev = {value:key for (key,value) in gender_master.items()}

    telephone_type = {
        "Not Classified" : 0,
        "Mobile Phone" : 1,
        "Home Phone" : 2,
        "Office Phone": 3
    }

    telephone_type_rev = {value:key for (key,value) in telephone_type.items()}

    address_categ = {
        "Permanent Address" : 1,
        "Residence Address" : 2,
        "Office Address": 3,
        "Not Categorized": 4
    }

    address_categ_rev = {value:key for (key,value) in address_categ.items()}

    residence_catg = {
        "Self/Owned/Family" : 1,
        "Rented/Employer/Others" : 2
    }

    residence_catg_rev = {value:key for (key,value) in residence_catg.items()}

    ownership_master = {
        "Individual":1, 
        "Authorised User":2,
        "Guarantor/Co-Applicant":3,
        "Joint":4
    }

    ownership_master_rev = {value:key for (key,value) in ownership_master.items()}

    collateral_master = {
        "No Collateral":0, 
        "Property":1,
        "Gold":2,
        "Shares":3,
        "Saving Account and Fixed Deposit":4,
        "Multiple Securities":5,
        "Others":6
    }

    collateral_master_rev = {value:key for (key,value) in collateral_master.items()}

    payment_freq = {
        "Weekly/Daily":1,
        "Fortnightly":2,
        "Monthly/Structured":3,
        "Quarterly":4,
        "Bullet Payment":5,
        "Daily":6,
        "Half yearly":7,
        "Yearly":8,
        "On-Demand":9
    }

    payment_freq_rev = {value:key for (key,value) in payment_freq.items()}

    credit_facility_status = {
        "Restructured":0,
        "Restructured Loan (Govt. Mandated)":1,
        "Written-off":2,
        "Settled":3,
        "Post (WO) Settled":4,
        "Account Sold":5,
        "Written Off and Account Sold":6,
        "Account Purchased":7,
        "Account Purchased and Written Off":8,
        "Account Purchased and Settled":9,
        "Account Purchased and Restructured":10,
        "Restructured due to Natural Calamity":11,
        "Restructured due to COVID-19":12,
        "Clear existing status":99
    }

    credit_facility_status_rev = {value:key for (key,value) in credit_facility_status.items()}
    
    columns_list = list(df.columns)

    for index, row in df.iterrows():

        try:
            if str(row["gender"]) != 'nan':
                value = gender_dict_rev[int(row["gender"])]
                df.at[index,'gender'] = value
        except Exception as e:
            print(e)

        try:
            if str(row["telephoneType"]) != 'nan':
                value = telephone_type_rev[int(row["telephoneType"])]
                df.at[index,'telephoneType'] = value
        except Exception as e:
            print(e)

        try:
            if str(row["stateCode"]) != 'nan':
                state_name = get_state_master_value(str(int(row["stateCode"])))
                df.at[index,'stateCode'] = state_name
        except Exception as e:
            print(e)

        try:
            if str(row["addressCategory"]) != 'nan':
                value = address_categ_rev[int(row["addressCategory"])]
                df.at[index,'addressCategory'] = value
        except Exception as e:
            print(e)
    
        try:
            if str(row["residenceCode"]) != 'nan':
                value = residence_catg_rev[int(row["residenceCode"])]
                df.at[index,'residenceCode'] = value
        except Exception as e:
            print(e)

        try:
            account_type_list = [i for i in columns_list if "accountType" in str(i) ]
            
            for account_t in account_type_list:
                if str(row[f"{account_t}"]) != 'nan':
                    if int(row[f"{account_t}"])/10 >= 1:
                        account_type = get_account_type(str(int(row[f"{account_t}"])))
                        df.at[index,f'{account_t}'] = account_type
                    else:
                        account_code = str(int(row[f"{account_t}"]))
                        account_type = get_account_type(f'''0{account_code}''')
                        df.at[index,f'{account_t}'] = account_type
        except Exception as e:
            print(e)

        try:
            if str(row["ownershipIndicator"]) != 'nan':
                value = ownership_master_rev[int(row["ownershipIndicator"])]
                df.at[index,'ownershipIndicator'] = value
        except Exception as e:
            print(e)


        try:
            if str(row["collateralType"]) != 'nan':
                value = collateral_master_rev[int(row["collateralType"])]
                df.at[index,'collateralType'] = value
        except Exception as e:
            print(e)

        try:
            if str(row["paymentFrequency"]) != 'nan':
                try:
                    value = payment_freq_rev[int(row["paymentFrequency"])]
                    # print(value)
                    df.at[index,'paymentFrequency'] = value
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

        try:
            if str(row["enquiryPurpose"]) != 'nan':
                if int(row["enquiryPurpose"])/10 >= 1:
                    print(row["enquiryPurpose"])
                    account_type = get_account_type(str(int(row["enquiryPurpose"])))
                    df.at[index,'enquiryPurpose'] = account_type
                else:
                    account_type = get_account_type(f'''0{int(row["enquiryPurpose"])}''')
                    df.at[index,'enquiryPurpose'] = account_type
        except Exception as e:
            print(e)

        try:
            if str(row["creditFacilityStatus"]) != 'nan':
                value = credit_facility_status_rev[int(row["creditFacilityStatus"])]
                # print(value)
                df.at[index,'creditFacilityStatus'] = value
        except Exception as e:
            print(e)

    
    return df

def get_max_dpd_value(row):
    max_dpd = 0
    for i in row:
        if str(i) != 'nan':
            if str(i) == 'LSS':
                max_dpd = 'LSS'
                break
            elif max_dpd != 'LSS' and str(i) == 'DBT':
                max_dpd = 'DBT' 
            elif max_dpd != 'LSS' and max_dpd != 'DBT' and str(i) == 'SUB':
                max_dpd = 'SUB' 
            elif max_dpd != 'LSS' and max_dpd != 'DBT' and str(i) != 'SUB' and "str" not in str(type(max_dpd))  :
                if int(float(i)) > int(float(max_dpd)):
                    max_dpd = int(float(i)) 
            else:
                pass

    return max_dpd



def update_and_pivot(df):
    # from datetime import datetime
    df["MONTH"] = pd.to_datetime(df["MONTH"],format='%B-%Y')
    df["ACCOUNT NO"] = [int(str(i).replace("Account No","")) for i in df["ACCOUNT NO"]]
    
    pivot_df = df.pivot(index='ACCOUNT NO',columns="MONTH",values='DPD')
    
    pivot_df = pivot_df.sort_index(ascending=False,axis=1)
    pivot_df = pivot_df.sort_index(axis=0)
 
    final_df = pd.DataFrame()
    
    print(pivot_df)

    for account in pivot_df.index:
        account_data = pivot_df[pivot_df.index == account]
        months = list(account_data.columns)  # Exclude 'Account number'
        dpd_values = list(account_data.values[0])  # Exclude 'Account number' value
        
        filtered_months = [months[i] for i in range(len(months)) if pd.notna(dpd_values[i])]

        print(dpd_values)
        filtered_dpd_values = [dpd_values[i] for i in range(len(dpd_values)) if pd.notna(dpd_values[i])]
                    
        filtered_dpd_values = [str(i).replace("SMA","030") for i in filtered_dpd_values]

        filtered_dpd_values = [str(i).replace("STD","000") for i in filtered_dpd_values]

        filtered_dpd_values = [str(i).replace("XXX","000") for i in filtered_dpd_values]
        
        filtered_dpd_values_final = []
        
        for i in range(len(filtered_dpd_values)):
            if pd.notna(filtered_dpd_values[i]):
                if str(filtered_dpd_values[i]).strip() not in ["LSS","DBT","SUB"]:
                    if len(str(int(float(filtered_dpd_values[i])))) == 1:
                        filtered_dpd_values_final.append(f"00{str(int(float(filtered_dpd_values[i])))}")
                    elif len(str(int(float(filtered_dpd_values[i])))) == 2:
                        filtered_dpd_values_final.append(f"0{str(int(float(filtered_dpd_values[i])))}")
                    elif len(str(int(float(filtered_dpd_values[i])))) == 3:
                        filtered_dpd_values_final.append(f"{str(int(float(filtered_dpd_values[i])))}")
                else:
                    filtered_dpd_values_final.append(filtered_dpd_values[i])
          
        filtered_dpd_values = filtered_dpd_values_final
        
        max_dpd = get_max_dpd_value(filtered_dpd_values)
        
        filtered_months = [datetime.datetime.strftime(month,'%B-%Y') for month in filtered_months]
        
        if len(str(max_dpd)) == 1:
            max_dpd = f"00{max_dpd}"
        elif len(str(max_dpd)) == 2:
            max_dpd = f"0{max_dpd}"
        else:
            max_dpd = f"{max_dpd}"
        
        new_data = [[f"Account No {account}"] + ["MAX_DPD"] + filtered_months,["DPD_VALUES"]+ [max_dpd] + filtered_dpd_values]

        new_df = pd.DataFrame(new_data)     
        

        new_df.loc[2] = ''
        
        final_df = pd.concat([final_df, new_df], axis=0)
    

    final_df.reset_index(drop=True, inplace=True)

    return final_df


def highlight_condition_index_rows(row):
    styles = []
    if (row.name - 1) % 3 == 0:
        value_to_highlight = str(row[1])
        if len(value_to_highlight) == 1:
            value_to_highlight = f"00{value_to_highlight}"
        elif len(value_to_highlight) == 2:
            value_to_highlight = f"0{value_to_highlight}"
        else:
            value_to_highlight = value_to_highlight
            
        value_dpd_value = "DPD_VALUES"
        first_flag = False
        for cell in row:
            if str(cell) != 'nan':
                if str(cell) != '000':
                    if str(cell) == value_to_highlight and first_flag is False :
                        first_flag = True
                        styles.append('background-color:#54BF2F; color:white; border:1px solid black')
                    elif str(cell) == value_to_highlight and first_flag is True:
                        styles.append('background-color:#FF5733; color:white; border:1px solid black')
                    else:
                        if str(cell) == value_dpd_value:
                            styles.append('background-color:#2C71BB; color:white; border:1px solid black' )
                        else:
                            styles.append('background-color:#E3EF69; color:black; border:1px solid black' )
                else:
                    if str(cell) == value_to_highlight and first_flag is False :
                        first_flag = True
                        styles.append('background-color:#54BF2F; color:white; border:1px solid black')
                    elif str(cell) == value_to_highlight and first_flag is True:
                        styles.append('background-color:#18BC0D; color:white; border:1px solid black')
                    else:
                        if str(cell) == value_dpd_value:
                            styles.append('background-color:#2C71BB; color:white; border:1px solid black' )
                        else:
                            styles.append('background-color:#E3EF69; color:black; border:1px solid black' )
            else:
                styles.append('')
    else:
        if (row.name) % 3 == 0:
            for cell in row:
                if str(cell) != 'nan':
                    styles.append('background-color:#2C71BB; color:white; border:1px solid black')
                else:
                    styles.append('')
        else:
            for cell in row:
                styles.append('') 
                
    return styles



def upload_files_to_sftp(file_name,dest_file_path):
    try:
        transport = paramiko.Transport((host, port))
        transport.connect(username=username, password=password)
        # print("Connection Established Successfully")
        sftp = paramiko.SFTPClient.from_transport(transport)
        remote_file = dest_file_path
        sftp.put(file_name,dest_file_path)
        print(f"Uploaded {file_name} to {dest_file_path}")
        sftp.close()
        transport.close()
    except Exception as e:
        print("ERROR:" , e)



def read_file_from_name_sheet_3(file_name):
    df = pd.read_excel(file_name,"OVERALL DATA",dtype=str)
    return df


def get_basic_summary_list_sheet_3(df):
    
    columns_list = list(df.columns)
    
    required_list_columns = ['scoreDate','score','oldestDateOpened','recentDateOpened','highCreditAmount.1','currentBalance.1','overdueBalance','inquiryPast30Days','inquiryPast12Months']

    for column in required_list_columns:
        if column not in columns_list:
            df[f'{column}'] = 0
        else:
            pass
        
    

    bureau_summary_df = df[['scoreDate','score','oldestDateOpened','recentDateOpened','highCreditAmount.1','currentBalance.1','overdueBalance','inquiryPast30Days','inquiryPast12Months']].dropna(axis=0)

    
    try:
        bureau_summary_df['scoreDate'] = bureau_summary_df['scoreDate'].astype(int)
        bureau_summary_df['scoreDate'] = bureau_summary_df['scoreDate'].astype(str)
        bureau_summary_df['scoreDate'] = bureau_summary_df['scoreDate'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])).strftime("%d-%m-%Y"))

        # bureau_summary_df['scoreDate'] = bureau_summary_df['scoreDate'].dt.strftime("%d-%m-%Y")
    except Exception:
        bureau_summary_df['scoreDate'] = None
        
    try:
        bureau_summary_df['oldestDateOpened'] = bureau_summary_df['oldestDateOpened'].astype(int)
        bureau_summary_df['oldestDateOpened'] = bureau_summary_df['oldestDateOpened'].astype(str)
        bureau_summary_df['oldestDateOpened'] = bureau_summary_df['oldestDateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])).strftime("%d-%m-%Y"))
        # bureau_summary_df['oldestDateOpened'] = bureau_summary_df['oldestDateOpened'].dt.strftime("%d-%m-%Y")
    except Exception:
        bureau_summary_df['oldestDateOpened'] = None
        
    try:
        bureau_summary_df['recentDateOpened'] = bureau_summary_df['recentDateOpened'].astype(int)
        bureau_summary_df['recentDateOpened'] = bureau_summary_df['recentDateOpened'].astype(str)
        bureau_summary_df['recentDateOpened'] = bureau_summary_df['recentDateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])).strftime("%d-%m-%Y"))
        # bureau_summary_df['recentDateOpened'] = bureau_summary_df['recentDateOpened'].dt.strftime("%d-%m-%Y")
    except Exception:
        bureau_summary_df['recentDateOpened'] = None
        
        
    # print(bureau_summary_df)

    bureau_summary_df['score'] = bureau_summary_df['score'].astype(int)
    bureau_summary_df['inquiryPast30Days'] = bureau_summary_df['inquiryPast30Days'].astype(int)
    bureau_summary_df['inquiryPast12Months'] = bureau_summary_df['inquiryPast12Months'].astype(int)
    
    # st.write("Summary")
    # st.write(bureau_summary_df)
    
    # print(bureau_summary_df)

    bureau_summary_list = list(bureau_summary_df.values[0])

    return bureau_summary_list


def get_total_business_loans_sheet_3(df):
    columns_list = list(df.columns)

    if 'accounts' in columns_list:
        return "Total count: 0, Total High Credit: 0, Total Outstanding: 0, Total EMI Value: 0"
    else:
        required_list_columns = ['index_accounts','accountType','dateReported.1','highCreditAmount','currentBalance','emiAmount']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass
            
        accounts = df[['index_accounts','accountType','dateReported.1','highCreditAmount','currentBalance','emiAmount']].dropna(axis=0)
        
        accounts['dateReported.1'] = accounts['dateReported.1'].astype(int)
        accounts['dateReported.1'] = accounts['dateReported.1'].astype(str)

        accounts['dateReported.1'] = accounts['dateReported.1'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        not_include_account_types = ['Gold Loan',
                'Credit Card',
                'Overdraft',
                'Non-Funded Credit Facility',
                'Loan Against Bank Deposits',
                'Fleet Card',
                'Corporate Credit Card',
                'Kisan Credit Card',
                'Loan on Credit Card',
                'Prime Minister Jaan Dhan Yojana – Overdraft',
                'Business Non-Funded Credit Facility – General',
                'Business Non-Funded Credit Facility – Priority Sector – Small Business',
                'Business Non-Funded Credit Facility – Priority Sector – Agriculture',
                'Business Non-Funded Credit Facility – Priority Sector-Others',
                'Priority Sector- Gold Loan',
                'Temporary Overdraft']

        accounts = accounts[~accounts['accountType'].isin(not_include_account_types)]
        accounts = accounts[accounts['currentBalance'] != 0]
        accounts['currentBalance'] = accounts['currentBalance'].apply(lambda x: float(x))
        accounts = accounts[accounts['currentBalance'].astype(float) > 10000.0]
        accounts['highCreditAmount'] = accounts['highCreditAmount'].apply(lambda x: float(x))
        accounts['emiAmount'] = accounts['emiAmount'].apply(lambda x: float(x))
        accounts['emiAmount_ini'] = accounts['emiAmount']

        for index,row in accounts.iterrows():
            if int(row['emiAmount']) == 0 and str(row['accountType']) in ["Housing Loan","Property Loan"]:
                if int(row['highCreditAmount']) == 0:
                    accounts.at[index,'emiAmount'] = row['currentBalance']*0.0150
                else:
                    accounts.at[index,'emiAmount'] = row['highCreditAmount']*0.0150
            elif int(row['emiAmount']) == 0 and str(row['accountType']) not in ["Housing Loan","Property Loan"]:
                if int(row['highCreditAmount']) == 0:
                    accounts.at[index,'emiAmount'] = row['currentBalance']*0.0375
                else:
                    accounts.at[index,'emiAmount'] = row['highCreditAmount']*0.0375

        # accounts.loc[accounts['emiAmount'] == 0.0 and ~accounts['accountType'].isin(["Housing Loan","Property Loan"]),'emiAmount'] = accounts['highCreditAmount']*0.0375
        # accounts.loc[accounts['emiAmount'] == 0.0 and accounts['accountType'].isin(["Housing Loan","Property Loan"]),'emiAmount'] = accounts['highCreditAmount']*0.0150
        # accounts.loc[accounts['emiAmount'] == 0.0,'emiAmount'] = accounts['currentBalance']*0.0375

        # st.write("Total business loans")
        # st.write(accounts)

        total_count = len(accounts)
        total_high_credit = accounts['highCreditAmount'].sum()
        total_outstanding = accounts['currentBalance'].sum()
        total_emi_value = accounts['emiAmount'].sum()

        result_string = f'''Total count: {total_count}, Total High Credit: {total_high_credit}, Total Outstanding: {total_outstanding}, Total EMI Value: {total_emi_value}'''

        return result_string

            
def get_fresh_sanction_loans_sheet_3(df):
    columns_list = list(df.columns)
    today = date.today()
    today_3M = today - dateutil.relativedelta.relativedelta(months=3)

    if 'accounts' in columns_list:
        return "Total count: 0, Total High Credit: 0, Total Outstanding: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance','emiAmount']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance','emiAmount']].dropna(axis=0)


        accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        accounts['dateOpened'] = accounts['dateOpened'].dt.date

        not_include_account_types = ['Gold Loan',
            'Loan Against Bank Deposits',
            'Priority Sector- Gold Loan']

        accounts = accounts[~accounts['accountType'].isin(not_include_account_types)]

        if len(accounts) != 0 :
            accounts = accounts[accounts['dateOpened'] >= today_3M ]

            total_count = len(accounts)
            total_high_credit = accounts['highCreditAmount'].sum()
            total_outstanding = accounts['currentBalance'].sum()
            
            result_string = f'''Total count: {total_count}, Total High Credit: {total_high_credit}, Total Outstanding: {total_outstanding}'''
        
            return result_string
        else:
            return "Total count: 0, Total High Credit: 0, Total Outstanding: 0"

def get_latest_loan_sheet_3(df):
    columns_list = list(df.columns)
    if 'accounts' in columns_list:
        return "Loan Date: None , Account Type: None , High Credit: None, Current Balance: None"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance','recentDateOpened']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']].dropna(axis=0)

        accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        accounts['dateOpened'] = accounts['dateOpened'].dt.date
        # accounts['dateOpened'] = accounts['dateOpened'].dt.strftime("%d %b %Y")

        not_include_account_types = ['Gold Loan',
            'Loan Against Bank Deposits',
            'Current Loan Against Bank Deposits',
            'Priority Sector- Gold Loan']

        accounts = accounts[~accounts['accountType'].isin(not_include_account_types)]

        if len(accounts) != 0:
            accounts = accounts[accounts['dateOpened'] == accounts['dateOpened'].max()]

            accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: x.strftime("%d %b %Y"))

            result_string = ""   
            count = 0 
            for index,row in accounts.iterrows():
                if count == 0 :
                    result_string = result_string + f'''Loan Date: {row[1]} , Account Type: {row[2]} , High Credit: {row[3]} , Current Balance: {row[4]}'''
                    count = count + 1
                elif count > 0 :
                    result_string = result_string + f'''|| Loan Date: {row[1]} , Account Type: {row[2]} , High Credit: {row[3]} , Current Balance: {row[4]}'''
                    count = count + 1

            return result_string
        else:
            return "Loan Date: None , Account Type: None , High Credit: None, Current Balance: None"

def get_highest_sanctions_loan_sheet_3(df):
    columns_list = list(df.columns)
    if 'accounts' in columns_list:
        return "Loan Date: None , Account Type: None , High Credit: None, Current Balance: None"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance','recentDateOpened']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']].dropna(axis=0)

        
        accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        accounts['dateOpened'] = accounts['dateOpened'].dt.date

        accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: x.strftime("%d %b %Y"))
        accounts['highCreditAmount'] = accounts['highCreditAmount'].astype(float)
        # accounts['recentDateOpened'] = pd.to_datetime(accounts['recentDateOpened'],format='%d%m%Y').dt.date

        not_include_account_types = ['Gold Loan',
            'Loan Against Bank Deposits',
            'Priority Sector- Gold Loan']

        accounts = accounts[~accounts['accountType'].isin(not_include_account_types)]

        if len(accounts) != 0 :
            accounts = accounts[accounts['highCreditAmount'] == accounts['highCreditAmount'].max()]

            result_string = ""

            count = 0 
            for index,row in accounts.iterrows():
                if count == 0 :
                    result_string = result_string + f'''Loan Date: {row[1]} , Account Type: {row[2]} , High Credit: {row[3]} , Current Balance: {row[4]}'''
                    count = count + 1
                elif count > 0 :
                    result_string = result_string + f'''|| Loan Date: {row[1]} , Account Type: {row[2]} , High Credit: {row[3]} , Current Balance: {row[4]}'''
                    count = count + 1

            return result_string
        else:
            return "Loan Date: None , Account Type: None , High Credit: None, Current Balance: None"


def get_payment_history_data_sheet_3(temp_result_df):

    # print(temp_result_df[["paymentHistory","paymentStartDate","paymentEndDate"]])

    temp_result_df['paymentStartDate'] = pd.to_datetime(temp_result_df['paymentStartDate'], format='%d%m%Y') 
    temp_result_df['paymentEndDate'] =pd.to_datetime(temp_result_df['paymentEndDate'], format='%d%m%Y') 
    temp_result_df['paymentStartDate'] = temp_result_df['paymentStartDate'].dt.strftime('%B-%Y')
    temp_result_df['paymentEndDate'] = temp_result_df['paymentEndDate'].dt.strftime('%B-%Y')
    temp_result_df['paymentStartDate'] = pd.to_datetime(temp_result_df['paymentStartDate'],format='%B-%Y')
    temp_result_df['paymentEndDate'] = pd.to_datetime(temp_result_df['paymentEndDate'],format='%B-%Y')  
    final_list = []

    for index,row in temp_result_df.iterrows():
        payment_history_string = str(row["paymentHistory"])
        payment_history_string_list = [payment_history_string[i:i+3] for i in range(0, len(payment_history_string), 3)]
        # st.write(payment_history_string_list)
        payment_start_date = row["paymentStartDate"]
        payment_end_date = row["paymentEndDate"]

        current_date = row["paymentStartDate"]
        # print("START DATE:",current_date)
        # print("END DATE :",payment_end_date)
        
        
        i = 0 
        index2 = index
        

        try:
            current_date = current_date + relativedelta(months=1)
            while i < len(payment_history_string_list):
                current_date = current_date - relativedelta(months=1)
                temp_list = []
                try:
                    temp_list = [f"Account No {index2+1}",str(current_date)[0:10],payment_history_string_list[i]]
                    
                    final_list.append(temp_list)
                    # print(temp_list)
                except Exception as e:
                    print("INDEX OUT OF RANGE")
                
                i+=1
        except Exception as e:
            print(e)

            
        
    result_df = pd.DataFrame(final_list, 
                    columns = ['ACCOUNT NO' , 'MONTH' , 'DPD']) 
    
    result_df["MONTH"] =  pd.to_datetime(result_df['MONTH'], format='%Y-%m-%d') 

    return result_df



def get_current_overdues_sheet_3(df,dpd_df):
    columns_list = list(df.columns)
    today = date.today()
    # today_format = today.strftime('%B-%Y')
    print("GET_CURRENT_OVERDUES")

    if 'accounts' in columns_list:
        print("NO ACCOUNT DETAILS PRESENT")
        return "Total Count: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance','recentDateOpened','amountOverdue']
        

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass
        
        account_1 = df[['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance','amountOverdue']]
        print(account_1)

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance','amountOverdue']].dropna(axis=0)

        print(accounts)

        accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        accounts['dateOpened'] = accounts['dateOpened'].dt.date
        print(accounts['dateOpened'])

        accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: x.strftime("%d %b %Y"))
        accounts['highCreditAmount'] = accounts['highCreditAmount'].astype(float)
        accounts['amountOverdue'] = accounts['amountOverdue'].astype(float)
        print("Amount overdues before filtering",accounts['amountOverdue'])
        
        print("DEBUG 1")

        accounts = accounts[accounts['amountOverdue'].astype(float) > 10000.0]
        
        print("DEBUG 2")
        print(accounts['amountOverdue'])

        total_accounts = len(accounts)
        print("DEBUG 3")

        if len(accounts) != 0 :
            result_string = f"Total Accounts : {total_accounts}  \n\n"
            
            print("DEBUG 4")

            count = 0 
            for index,row in accounts.iterrows():
                print("ERROR 1",row[0][1:])
                print("ERROR 2",row)
                if str(row[0])[1:] != '' and row[0] is not None:
                    dpd_temp_df = dpd_df[dpd_df['ACCOUNT NO'] == f"Account No {int(str(row[0])[1:])}"]
                    # st.write(dpd_temp_df)
                    # st.write(dpd_temp_df['MONTH'].max())
                    dpd_temp_df = dpd_temp_df[dpd_temp_df['MONTH'] == dpd_temp_df['MONTH'].max()].dropna(axis=0)
    
                    dpd_temp_df['MONTH'] = dpd_temp_df['MONTH'].dt.strftime('%B-%Y')
                
                    dpd_temp_df = list(dpd_temp_df.values[0])
                    result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} , Current Balance: {row[4]} , Current Overdue: {row[5]} , Latest Month : {dpd_temp_df[1]} , Latest DPD : {dpd_temp_df[2]} \n\n'''
                    print(result_string)
                    count = count + 1
                else:
                    pass
            
            print(result_string)
            return result_string
        else:
            print("DEBUG 4")
            return "Total Count: 0"


def get_max_dpd_value_sheet_3(dpd_list):
    max_dpd = 0
    for i in dpd_list:
        if str(i) != 'nan':
            if str(i) == 'LSS':
                max_dpd = 'LSS'
                break
            elif max_dpd != 'LSS' and str(i) == 'DBT':
                max_dpd = 'DBT' 
            elif max_dpd != 'LSS' and max_dpd != 'DBT' and str(i) == 'SUB':
                max_dpd = 'SUB' 
            elif max_dpd != 'LSS' and max_dpd != 'DBT' and str(i) != 'SUB' and "str" not in str(type(max_dpd))  :
                if int(float(i)) > int(float(max_dpd)):
                    max_dpd = int(float(i))
                else:
                    pass
    return str(max_dpd)




def get_past_overdues_60_sheet_3(df,dpd_df):
    columns_list = list(df.columns)
    today = date.today()
    # today_format = today.strftime('%B-%Y')

    if 'accounts' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount']].dropna(axis=0)

        not_include_account_types = ['Gold Loan',
            'Loan Against Bank Deposits',
            'Priority Sector- Gold Loan']

        accounts = accounts[~accounts['accountType'].isin(not_include_account_types)]

        if len(accounts) != 0:
            accounts['dateOpened'] = accounts['dateOpened'].astype(int)
            accounts['dateOpened'] = accounts['dateOpened'].astype(str)
            
            accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

            accounts['dateOpened'] = accounts['dateOpened'].dt.date

            accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: x.strftime("%d %b %Y"))
            accounts['highCreditAmount'] = accounts['highCreditAmount'].astype(float)

            total_accounts = len(accounts)

            result_string = ""

            count = 0 
            for index,row in accounts.iterrows():
                if str(row[0])[1:] != '' and row[0] is not None:
                    dpd_temp_df = dpd_df[dpd_df['ACCOUNT NO'] == f"Account No {int(str(row[0])[1:])}"]
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'SMA', 'DPD'] = '030'
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'STD', 'DPD'] = '000'
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'XXX', 'DPD'] = '000'
                    dpd_list = list(dpd_temp_df['DPD'])
                    dpd_list_ini = dpd_list
                    dpd_list = list(map(lambda x: x.replace('SMA', '030'), dpd_list))
                    dpd_list = list(map(lambda x: x.replace('STD', '000'), dpd_list))
                    dpd_list = list(map(lambda x: x.replace('XXX', '000'), dpd_list))
    
                    
    
                    max_dpd_str = get_max_dpd_value_sheet_3(dpd_list)
    
                    if len(str(max_dpd_str)) == 1:
                        max_dpd = f"00{max_dpd_str}"
                    elif len(str(max_dpd_str)) == 2:
                        max_dpd = f"0{max_dpd_str}"
                    else:
                        max_dpd = f"{max_dpd_str}"
    
                    # if  > 60:
                    dpd_temp_df_2 = dpd_temp_df[dpd_temp_df['DPD'] == max_dpd].dropna(axis=0)
                    dpd_temp_df_2 = dpd_temp_df_2[dpd_temp_df_2['MONTH'] == dpd_temp_df_2['MONTH'].max()].dropna(axis=0)
                    dpd_temp_df_2['MONTH'] = dpd_temp_df_2['MONTH'].dt.strftime('%B-%Y')
    
                    dpd_temp_df = dpd_temp_df[dpd_temp_df['MONTH'] == dpd_temp_df['MONTH'].max()].dropna(axis=0)
                    dpd_temp_df['MONTH'] = dpd_temp_df['MONTH'].dt.strftime('%B-%Y')
    
                    dpd_temp_df_list = list(dpd_temp_df.values[0])
                    try:
                        dpd_temp_df_list_2 = list(dpd_temp_df_2.values[0])
                        if dpd_temp_df_list_2[2] in ['DBT','LSS','SUB']:
                            result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} ,  Max DPD Month : {dpd_temp_df_list_2[1]} , Max DPD : {dpd_temp_df_list_2[2]}  , Latest DPD Month : {dpd_temp_df_list[1]} , Latest DPD : {dpd_temp_df_list[2]} \n\n'''
                            count = count + 1
                        elif int(dpd_temp_df_list_2[2]) > 60 :
                            result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} ,  Max DPD Month : {dpd_temp_df_list_2[1]} , Max DPD : {dpd_temp_df_list_2[2]}  , Latest DPD Month : {dpd_temp_df_list[1]} , Latest DPD : {dpd_temp_df_list[2]} \n\n'''
                            count = count + 1
                    except Exception as e:
                        print(f"Account No {int(str(row[0])[1:])}")
                        print(max_dpd)
                        print(dpd_temp_df)
                        # st.write(f"Account No {int(str(row[0])[1:])}")
                        # st.write(max_dpd)
                        # st.write(dpd_temp_df)
                else:
                    pass

            result_string_total = F"Total Count: {count}  \n\n"
            result_string = result_string_total + result_string

            return result_string

        else:
            return "Total Count: 0"


def get_past_overdues_30_sheet_3(df,dpd_df):
    columns_list = list(df.columns)
    today = date.today()
    today_5M = today - dateutil.relativedelta.relativedelta(months=6)

    if 'accounts' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']].dropna(axis=0)

        not_include_account_types = ['Gold Loan',
            'Loan Against Bank Deposits',
            'Priority Sector- Gold Loan']

        accounts = accounts[~accounts['accountType'].isin(not_include_account_types)]

        accounts = accounts[accounts['currentBalance'].astype(float) > 10000.0]

        # accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        # accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        # accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])) if len(x) >= 9 )
        
        # print(accounts['dateOpened'])

        # accounts['dateOpened'] = accounts['dateOpened'].dt.date

        # accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: x.strftime("%d %b %Y"))
        accounts['highCreditAmount'] = accounts['highCreditAmount'].astype(float)

        total_accounts = len(accounts)

        if len(accounts) != 0:

            result_string = ""

            count = 0 
            for index,row in accounts.iterrows():
                if str(row[0])[1:] != '' and row[0] is not None:
                    dpd_temp_df = dpd_df[dpd_df['ACCOUNT NO'] == f"Account No {int(str(row[0])[1:])}"]
                    dpd_temp_df = dpd_temp_df[dpd_temp_df['MONTH'].dt.date >= today_5M]
                    # st.write(dpd_temp_df)
                    # st.write(today_5M)
    
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'SMA', 'DPD'] = '030'
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'STD', 'DPD'] = '000'
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'XXX', 'DPD'] = '000'
                    dpd_list = list(dpd_temp_df['DPD'])
                    dpd_list_ini = dpd_list
                    dpd_list = list(map(lambda x: x.replace('SMA', '030'), dpd_list))
                    dpd_list = list(map(lambda x: x.replace('STD', '000'), dpd_list))
                    dpd_list = list(map(lambda x: x.replace('XXX', '000'), dpd_list))
    
                    
    
                    max_dpd_str = get_max_dpd_value_sheet_3(dpd_list)
    
                    if len(str(max_dpd_str)) == 1:
                        max_dpd = f"00{max_dpd_str}"
                    elif len(str(max_dpd_str)) == 2:
                        max_dpd = f"0{max_dpd_str}"
                    else:
                        max_dpd = f"{max_dpd_str}"
    
                    # if  > 60:
                    dpd_temp_df_2 = dpd_temp_df[dpd_temp_df['DPD'] == max_dpd].dropna(axis=0)
                    # st.write(dpd_temp_df_2)
                    dpd_temp_df_2 = dpd_temp_df_2[dpd_temp_df_2['MONTH'] == dpd_temp_df_2['MONTH'].max()].dropna(axis=0)
                    # st.write(dpd_temp_df_2)
                    # st.write("========================")
                    dpd_temp_df_2['MONTH'] = dpd_temp_df_2['MONTH'].dt.strftime('%B-%Y')
    
                    dpd_temp_df = dpd_temp_df[dpd_temp_df['MONTH'] == dpd_temp_df['MONTH'].max()].dropna(axis=0)
                    dpd_temp_df['MONTH'] = dpd_temp_df['MONTH'].dt.strftime('%B-%Y')
    
                    if len(dpd_temp_df_2) != 0 and len(dpd_temp_df) != 0:
                        dpd_temp_df_list = list(dpd_temp_df.values[0])
                        try:
                            dpd_temp_df_list_2 = list(dpd_temp_df_2.values[0])
                            if dpd_temp_df_list_2[2] in ['DBT','LSS','SUB']:
                                result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} ,  Max DPD Month : {dpd_temp_df_list_2[1]} , Max DPD : {dpd_temp_df_list_2[2]}  , Latest DPD Month : {dpd_temp_df_list[1]} , Latest DPD : {dpd_temp_df_list[2]} \n\n'''
                                count = count + 1
                            elif int(dpd_temp_df_list_2[2]) > 30 :
                                result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} ,  Max DPD Month : {dpd_temp_df_list_2[1]} , Max DPD : {dpd_temp_df_list_2[2]}  , Latest DPD Month : {dpd_temp_df_list[1]} , Latest DPD : {dpd_temp_df_list[2]} \n\n'''
                                count = count + 1
                        except Exception as e:
                            print(f"Account No {int(str(row[0])[1:])}")
                else:
                    pass

            result_string_total = F"Total Count: {count}  \n\n"
            result_string = result_string_total + result_string
            
            return result_string
        else:
            return "Total Count: 0"


def get_past_overdues_60_2_sheet_3(df,dpd_df):
    columns_list = list(df.columns)
    today = date.today()
    today_8M = today - dateutil.relativedelta.relativedelta(months=9)

    if 'accounts' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']].dropna(axis=0)

        not_include_account_types = ['Gold Loan',
            'Loan Against Bank Deposits',
            'Priority Sector- Gold Loan']

        accounts = accounts[~accounts['accountType'].isin(not_include_account_types)]

        accounts = accounts[accounts['currentBalance'].astype(float) > 10000.0]


        # accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        # accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        # accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        # accounts['dateOpened'] = accounts['dateOpened'].dt.date

        # accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: x.strftime("%d %b %Y"))
        
        accounts['highCreditAmount'] = accounts['highCreditAmount'].astype(float)

        total_accounts = len(accounts)

        if len(accounts) != 0 :
            result_string = ""

            count = 0 
            for index,row in accounts.iterrows():
                if str(row[0])[1:] != '' and row[0] is not None:
                    dpd_temp_df = dpd_df[dpd_df['ACCOUNT NO'] == f"Account No {int(str(row[0])[1:])}"]
                    dpd_temp_df = dpd_temp_df[dpd_temp_df['MONTH'].dt.date >= today_8M]
                    # st.write(dpd_temp_df)
                    # st.write(today_5M)
    
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'SMA', 'DPD'] = '030'
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'STD', 'DPD'] = '000'
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'XXX', 'DPD'] = '000'
                    dpd_list = list(dpd_temp_df['DPD'])
                    dpd_list_ini = dpd_list
                    dpd_list = list(map(lambda x: x.replace('SMA', '030'), dpd_list))
                    dpd_list = list(map(lambda x: x.replace('STD', '000'), dpd_list))
                    dpd_list = list(map(lambda x: x.replace('XXX', '000'), dpd_list))
    
                    
    
                    max_dpd_str = get_max_dpd_value_sheet_3(dpd_list)
    
                    if len(str(max_dpd_str)) == 1:
                        max_dpd = f"00{max_dpd_str}"
                    elif len(str(max_dpd_str)) == 2:
                        max_dpd = f"0{max_dpd_str}"
                    else:
                        max_dpd = f"{max_dpd_str}"
    
                    # if  > 60:
                    dpd_temp_df_2 = dpd_temp_df[dpd_temp_df['DPD'] == max_dpd].dropna(axis=0)
                    # st.write(dpd_temp_df_2)
                    dpd_temp_df_2 = dpd_temp_df_2[dpd_temp_df_2['MONTH'] == dpd_temp_df_2['MONTH'].max()].dropna(axis=0)
                    # st.write(dpd_temp_df_2)
                    # st.write("========================")
                    dpd_temp_df_2['MONTH'] = dpd_temp_df_2['MONTH'].dt.strftime('%B-%Y')
    
                    dpd_temp_df = dpd_temp_df[dpd_temp_df['MONTH'] == dpd_temp_df['MONTH'].max()].dropna(axis=0)
                    dpd_temp_df['MONTH'] = dpd_temp_df['MONTH'].dt.strftime('%B-%Y')
    
                    if len(dpd_temp_df_2) != 0 and len(dpd_temp_df) != 0:
                        dpd_temp_df_list = list(dpd_temp_df.values[0])
                        try:
                            dpd_temp_df_list_2 = list(dpd_temp_df_2.values[0])
                            if dpd_temp_df_list_2[2] in ['DBT','LSS','SUB']:
                                result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} ,  Max DPD Month : {dpd_temp_df_list_2[1]} , Max DPD : {dpd_temp_df_list_2[2]}  , Latest DPD Month : {dpd_temp_df_list[1]} , Latest DPD : {dpd_temp_df_list[2]} \n\n'''
                                count = count + 1
                            elif int(dpd_temp_df_list_2[2]) > 60 :
                                result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} ,  Max DPD Month : {dpd_temp_df_list_2[1]} , Max DPD : {dpd_temp_df_list_2[2]}  , Latest DPD Month : {dpd_temp_df_list[1]} , Latest DPD : {dpd_temp_df_list[2]} \n\n'''
                                count = count + 1
                        except Exception as e:
                            print(f"Account No {int(str(row[0])[1:])}")
                else:
                    pass

            result_string_total = F"Total Count: {count}  \n\n"
            result_string = result_string_total + result_string
            return result_string
        else:
            return "Total Count: 0"


def get_past_overdues_90_sheet_3(df,dpd_df):
    columns_list = list(df.columns)
    today = date.today()
    today_3Y = today - dateutil.relativedelta.relativedelta(years=3)
    today_3Y = today_3Y - dateutil.relativedelta.relativedelta(months=2)

    if 'accounts' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','currentBalance']].dropna(axis=0)

        not_include_account_types = ['Gold Loan',
            'Loan Against Bank Deposits',
            'Priority Sector- Gold Loan']

        accounts = accounts[~accounts['accountType'].isin(not_include_account_types)]

        # accounts = accounts[accounts['currentBalance'] > 5000]

        if len(accounts) != 0:

            accounts['dateOpened'] = accounts['dateOpened'].astype(int)
            accounts['dateOpened'] = accounts['dateOpened'].astype(str)
            
            accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

            accounts['dateOpened'] = accounts['dateOpened'].dt.date

            accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: x.strftime("%d %b %Y"))
            accounts['highCreditAmount'] = accounts['highCreditAmount'].astype(float)


            total_accounts = len(accounts)

            result_string = ""

            count = 0 
            for index,row in accounts.iterrows():
                if str(row[0])[1:] != '' and row[0] is not None:
                    dpd_temp_df = dpd_df[dpd_df['ACCOUNT NO'] == f"Account No {int(str(row[0])[1:])}"]
                    dpd_temp_df = dpd_temp_df[dpd_temp_df['MONTH'].dt.date >= today_3Y]
    
    
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'SMA', 'DPD'] = '030'
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'STD', 'DPD'] = '000'
                    dpd_temp_df.loc[dpd_temp_df['DPD'] == 'XXX', 'DPD'] = '000'
                    dpd_list = list(dpd_temp_df['DPD'])
                    dpd_list_ini = dpd_list
                    dpd_list = list(map(lambda x: x.replace('SMA', '030'), dpd_list))
                    dpd_list = list(map(lambda x: x.replace('STD', '000'), dpd_list))
                    dpd_list = list(map(lambda x: x.replace('XXX', '000'), dpd_list))
    
                    
    
                    max_dpd_str = get_max_dpd_value_sheet_3(dpd_list)
    
                    if len(str(max_dpd_str)) == 1:
                        max_dpd = f"00{max_dpd_str}"
                    elif len(str(max_dpd_str)) == 2:
                        max_dpd = f"0{max_dpd_str}"
                    else:
                        max_dpd = f"{max_dpd_str}"
    
                    dpd_temp_df_2 = dpd_temp_df[dpd_temp_df['DPD'] == max_dpd].dropna(axis=0)
                    dpd_temp_df_2 = dpd_temp_df_2[dpd_temp_df_2['MONTH'] == dpd_temp_df_2['MONTH'].max()].dropna(axis=0)
    
                    dpd_temp_df_2['MONTH'] = dpd_temp_df_2['MONTH'].dt.strftime('%B-%Y')
    
                    dpd_temp_df = dpd_temp_df[dpd_temp_df['MONTH'] == dpd_temp_df['MONTH'].max()].dropna(axis=0)
                    dpd_temp_df['MONTH'] = dpd_temp_df['MONTH'].dt.strftime('%B-%Y')
    
                    if len(dpd_temp_df_2) != 0 and len(dpd_temp_df) != 0:
                        dpd_temp_df_list = list(dpd_temp_df.values[0])
                        try:
                            dpd_temp_df_list_2 = list(dpd_temp_df_2.values[0])
                            if dpd_temp_df_list_2[2] in ['DBT','LSS','SUB']:
                                result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} ,  Max DPD Month : {dpd_temp_df_list_2[1]} , Max DPD : {dpd_temp_df_list_2[2]}  , Latest DPD Month : {dpd_temp_df_list[1]} , Latest DPD : {dpd_temp_df_list[2]} \n\n'''
                                count = count + 1
                            elif int(dpd_temp_df_list_2[2]) >= 90 :
                                result_string = result_string + f'''|| Account Type: {row[2]} , High Credit: {row[3]} ,  Max DPD Month : {dpd_temp_df_list_2[1]} , Max DPD : {dpd_temp_df_list_2[2]}  , Latest DPD Month : {dpd_temp_df_list[1]} , Latest DPD : {dpd_temp_df_list[2]} \n\n'''
                                count = count + 1
                        except Exception as e:
                            print(f"Account No {int(str(row[0])[1:])}")
                else:
                    pass
                
            result_string_total = F"Total Count: {count}  \n\n"
            result_string = result_string_total + result_string
            
            return result_string

        else:
            return "Total Count: 0"


def get_restructured_count_sheet_3(df):
    columns_list = list(df.columns)
    today = date.today()
    # today_2Y = today - dateutil.relativedelta.relativedelta(years=2)

    if 'accounts' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','creditFacilityStatus']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','creditFacilityStatus']].dropna(axis=0)

        # accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        # accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        # accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        # accounts['dateOpened'] = accounts['dateOpened'].dt.date

    
        restructured_list = ['Restructured','Restructured due to COVID-19','Restructured Loan (Govt. Mandated)','Restructured due to Natural Calamity','Restructured & Closed']

        accounts = accounts[accounts['creditFacilityStatus'].isin(restructured_list)]

        if len(accounts) != 0 :
            total_accounts = len(accounts)

            result_string = f"Total Accounts : {total_accounts} "

            return result_string
        else:
            return "Total Accounts : 0"


def get_written_off_count_sheet_3(df):
    columns_list = list(df.columns)
    today = date.today()
    # today_3Y = today - dateutil.relativedelta.relativedelta(years=3)

    if 'accounts' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','creditFacilityStatus','woAmountTotal','woAmountPrincipal']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','creditFacilityStatus','woAmountTotal','woAmountPrincipal']].dropna(axis=0)

        # accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        # accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        # accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        # accounts['dateOpened'] = accounts['dateOpened'].dt.date

        

        written_off_list = ['Written-off','Written Off and Account Sold','Account Purchased and Written Off','Post Write Off Closed','Post (WO) Settled']

        accounts = accounts[accounts['creditFacilityStatus'].isin(written_off_list)]


        total_accounts = len(accounts)

        if len(accounts) != 0:

            wo_amount_total = accounts['woAmountTotal'].sum()
            wo_amount_principal = accounts['woAmountPrincipal'].sum()

            result_string = f"Total Accounts : {total_accounts} , Total Written Off Amount : {wo_amount_total} , Total Written Off Principal: {wo_amount_principal} "

            return result_string
        else:
            return "Total Accounts : 0"




def get_settlement_count_sheet_3(df):
    columns_list = list(df.columns)
    today = date.today()
    # today_3Y = today - dateutil.relativedelta.relativedelta(years=3)

    if 'accounts' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_accounts','dateOpened','accountType','highCreditAmount','creditFacilityStatus','settlementAmount']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_accounts','dateOpened','accountType','highCreditAmount','creditFacilityStatus','settlementAmount']].dropna(axis=0)

        # accounts['dateOpened'] = accounts['dateOpened'].astype(int)
        # accounts['dateOpened'] = accounts['dateOpened'].astype(str)
        
        # accounts['dateOpened'] = accounts['dateOpened'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))

        # accounts['dateOpened'] = accounts['dateOpened'].dt.date

        

        settled_list = ['Settled','Post (WO) Settled']

        accounts = accounts[accounts['creditFacilityStatus'].isin(settled_list)]


        total_accounts = len(accounts)

        if len(accounts) != 0 :

            settled_amount_total = accounts['settlementAmount'].sum()

            result_string = f"Total Accounts : {total_accounts} , Total Settlement Amount : {settled_amount_total} "

            return result_string
        else:
            return "Total Accounts : 0"


def get_business_loan_enq_sheet_3(df):
    columns_list = list(df.columns)
    today = date.today()
    today_5M = today - dateutil.relativedelta.relativedelta(months=3)

    if 'enquiries' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_enquiry','enquiryPurpose','enquiryAmount','enquiryDate']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_enquiry','enquiryPurpose','enquiryAmount','enquiryDate']].dropna(axis=0)

        business_enquiry_list = ["Auto Loan (Personal)","Auto Loan (Personal)","Housing Loan","Property Loan","Loan Against Shares/Securities","Personal Loan","Consumer Loan","Gold Loan","Education Loan","Loan to Professional","Credit Card","Leasing","Overdraft","Two-wheeler Loan","Non-Funded Credit Facility","Loan Against Bank Deposits","Fleet Card","Commercial Vehicle Loan","Telco – Wireless","Telco – Broadband","Telco – Landline","Seller Financing","Seller Financing Soft (Applicable to Enquiry Purpose only)","GECL Loan Secured","GECL Loan Unsecured","Secured Credit Card","Used Car Loan","Construction Equipment Loan","Tractor Loan","Corporate Credit Card","Kisan Credit Card","Loan on Credit Card","Prime Minister Jaan Dhan Yojana – Overdraft","Mudra Loans – Shishu / Kishor / Tarun","Microfinance – Personal Loan","Microfinance – Housing Loan","Microfinance – Other","Pradhan Mantri Awas Yojana - Credit Link Subsidy Scheme MAY CLSS","P2P Personal Loan","P2P Auto Loan","P2P Education Loan","Business Non-Funded Credit Facility – General","Business Non-Funded Credit Facility – Priority Sector – Small Business","Business Non-Funded Credit Facility – Priority Sector – Agriculture","Business Non-Funded Credit Facility – Priority Sector-Others","Business Loan Against Bank Deposits","Insurance","Short Term Personal Loan","Priority Sector- Gold Loan","Temporary Overdraft","Microfinance Detailed Report (Applicable to Enquiry Purpose only)","Summary Report (Applicable to Enquiry Purpose only)","Locate Plus for Insurance (Applicable to Enquiry Purpose only)","Account Review (Applicable to Enquiry Purpose only)","Retro Enquiry (Applicable to Enquiry Purpose only)","Locate Plus (Applicable to Enquiry Purpose only)","Other","Adviser Liability (Applicable to Enquiry Purpose only)","Secured (Account Group for Portfolio Review response)","Unsecured (Account Group for Portfolio Review response)"]

        accounts = accounts[~accounts['enquiryPurpose'].isin(business_enquiry_list)]

        if len(accounts['enquiryDate']) != 0:
            accounts['enquiryDate'] = accounts['enquiryDate'].astype(int)
            accounts['enquiryDate'] = accounts['enquiryDate'].astype(str)

            # st.write(accounts['enquiryDate'])
            
            accounts['enquiryDate'] = accounts['enquiryDate'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))


            accounts['enquiryDate'] = accounts['enquiryDate'].dt.date

            # st.write(accounts['enquiryDate'],today_5M)
            
            accounts = accounts[accounts['enquiryDate'] >= today_5M]

            

            # st.write("BUSINESS_LOAN_ENQUIRIES")
            # st.write(accounts)

            # accounts['dateOpened'] = accounts['dateOpened'].strftime("%d %B %Y")

            total_accounts = len(accounts)

            if len(accounts) != 0:
                total_enquiry_amount = accounts['enquiryAmount'].sum()
                # wo_amount_principal = accounts['woAmountPrincipal'].sum()

                result_string = f"Total Accounts : {total_accounts} ,  Total Enquiry Amount: : {total_enquiry_amount} "

                return result_string
            else:
                return "Total Count: 0"
        else:
            return "Total Count: 0"



def get_scf_loan_enq_sheet_3(df):
    columns_list = list(df.columns)
    today = date.today()
    today_5M = today - dateutil.relativedelta.relativedelta(months=3)

    if 'enquiries' in columns_list:
        return "Total Count: 0"
    else:
        required_list_columns = ['index_enquiry','enquiryPurpose','enquiryAmount','enquiryDate']

        for column in required_list_columns:
            if column not in columns_list:
                df[f'{column}'] = 0
            else:
                pass

        accounts = df[['index_enquiry','enquiryPurpose','enquiryAmount','enquiryDate']].dropna(axis=0)

        scf_enquiry_list = ["Seller Financing","Seller Financing Soft (Applicable to Enquiry Purpose only)"]

        accounts = accounts[accounts['enquiryPurpose'].isin(scf_enquiry_list)]

        if len(accounts['enquiryDate']) != 0:
            accounts['enquiryDate'] = accounts['enquiryDate'].astype(int)
            accounts['enquiryDate'] = accounts['enquiryDate'].astype(str)

            # st.write(len(accounts['enquiryDate']))
            
            accounts['enquiryDate'] = accounts['enquiryDate'].apply(lambda x: datetime.datetime(int(x[-4:]),int(x[-6:-4]), int(x[:-6])))


            accounts['enquiryDate'] = accounts['enquiryDate'].dt.date

            accounts = accounts[accounts['enquiryDate'] >= today_5M]

            # st.write("SCF_LOAN_ENQUIRIES")
            # st.write(accounts)

            # accounts['dateOpened'] = accounts['dateOpened'].strftime("%d %B %Y")

            total_accounts = len(accounts)

            if len(accounts) != 0:
                total_enquiry_amount = accounts['enquiryAmount'].sum()
                # wo_amount_principal = accounts['woAmountPrincipal'].sum()

                result_string = f"Total Accounts : {total_accounts} ,  Total Enquiry Amount: : {total_enquiry_amount} "

                return result_string
            else:
                return "Total Count: 0"
        else:
            return "Total Count: 0"



def highlight_condition_index_rows_sheet_3(row):
    styles = []
    if row.name == 1:
        for cell in row:
            if str(cell) != 'None' and str(cell) != 'nan' :
                styles.append('background-color:#1A5573; color:white; border:1px solid black')
            else:
                styles.append('')
    else:
        for cell in row:
            if str(cell) != 'None' and str(cell) != 'nan' :
                styles.append('border:1px solid black')
            else:
                styles.append('')

    return styles

def get_formatted_df_sheet_3(final_list):
    mainframe_df = []
    mainframe_df.append([])
    mainframe_df.append([None,"DATE OF BUREAU REPORT","BUREAU SCORE","OLDEST LOAN TAKEN DATE","LATEST LOAN TAKEN DATE","TOTAL HIGH CREDIT VALUE","CURRENT LOAN OUTSTANDING VALUE","TOTAL OVERDUE VALUE","TOTAL TERM LOANS (POS > 10K)","FRESH SANCTIONS IN PAST 3 MONTHS (EXCLUDING GOLD LOAN)","LATEST LOAN (EXCLUDING GOLD LOAN)","HIGHEST SANCTIONED LOAN (EXCLUDING GOLD LOAN)","CURRENT OVERDUES (> 10K)","PAST OVERDUES ( > 60 DPD)","PAST OVERDUES ( > 30 DPD) PAST 3 MONTHS (POS > 10K)","60+ DPD IN PAST 6 MONTHS (POS> 10K)","90&+/SUB/DBT/LSS DPD IN PAST 3 YEARS","RESTRUCTURED ACCOUNTS","WRITTEN OFF DETAILS","ACCOUNTS SETTLED","INQUIRIES IN PAST 1 MONTH","INQUIRIES IN PAST 12 MONTHS","BUSINESS LOAN ENQUIRIES IN PAST (3 MONTHS)","SELLER FINANCE LOAN ENQUIRIES IN PAST (3 MONTHS)"])

    values_list = [None]+final_list
    mainframe_df.append(values_list)

    mainframe_df_all = pd.DataFrame(mainframe_df)

    mainframe_df_formatted = mainframe_df_all.style.apply(highlight_condition_index_rows_sheet_3,axis=1)

    return mainframe_df_formatted
    


def main_sheet_3(file_created):
    file_name = file_created
    # file_name = 'key_error_detection.xlsx' 
    file_df = read_file_from_name_sheet_3(file_name)

    basic_summary_list = get_basic_summary_list_sheet_3(file_df)

    # getting Total Business loans string 
    total_business_loans = get_total_business_loans_sheet_3(file_df)

    # getting Fresh Sanctions in Past 3 Months
    fresh_sanction_loans = get_fresh_sanction_loans_sheet_3(file_df)

    # getting Latest Loan (Excluding GL)
    latest_loan = get_latest_loan_sheet_3(file_df)

    # getting Highest Loan Sanctions (Excluding GL)
    highest_sanction = get_highest_sanctions_loan_sheet_3(file_df)


    payment_history_df = get_payment_history_data_sheet_3(file_df)

    # getting current overdues
    try:
        current_overdues = get_current_overdues_sheet_3(file_df,payment_history_df)
    except Exception as e:
        current_overdues = 0
        print(e)

    # past Overdues
    try:
        past_overdues_60 = get_past_overdues_60_sheet_3(file_df,payment_history_df)
    except Exception as e:
        past_overdues_60 = 0
        print(e)

    try:
        past_overdues_30 = get_past_overdues_30_sheet_3(file_df,payment_history_df)
    except Exception as e:
        past_overdues_30 = 0
        print(e)

    try:
        past_overdue_60_2 = get_past_overdues_60_2_sheet_3(file_df,payment_history_df)
    except Exception as e:
        past_overdue_60_2 = 0
        print(e)

    try:
        past_overdues_90 = get_past_overdues_90_sheet_3(file_df,payment_history_df)
    except Exception as e:
        past_overdues_90 = 0
        print(e)

    try:
        restructured_account = get_restructured_count_sheet_3(file_df)
    except Exception as e:
        restructured_account = 0
        print(e)
    
    try:
        written_off_account = get_written_off_count_sheet_3(file_df)
    except Exception as e:
        written_off_account = 0
        print(e)

    try:
        settled_account = get_settlement_count_sheet_3(file_df)
    except Exception as e:
        settled_account = 0
        print(e)

    try:
        business_loan_enq = get_business_loan_enq_sheet_3(file_df)
    except Exception as e:
        business_loan_enq = 0
        print(e)

    try:
        scf_loan_enq = get_scf_loan_enq_sheet_3(file_df)
    except Exception as e:
        scf_loan_enq = 0
        print(e)


    final_list = basic_summary_list[0:7] + [total_business_loans] + [fresh_sanction_loans] + [latest_loan] + [highest_sanction] + [current_overdues] + [past_overdues_60] + [past_overdues_30] + [past_overdue_60_2] + [past_overdues_90] + [restructured_account] + [written_off_account] + [settled_account] + basic_summary_list[7:] + [business_loan_enq] + [scf_loan_enq]

    formatted_df = get_formatted_df_sheet_3(final_list)

    # st.write(formatted_df)

    # writer = pd.ExcelWriter("OUTPUT_DRAFT.xlsx", engine='openpyxl')
    # file_df.to_excel(writer, 'OVERALL DATA', index = False)
    # formatted_df.to_excel(writer, 'BUREAU SUMMARY', index = False)
    # writer._save()

    return formatted_df



def convert_json_to_etl(file,output_folder_path,sftp):
    
    s3 = boto3.resource('s3')
    
    df = pd.read_excel(file)

    # Defining a colomn in case of row not processed due to error.
    df["ERROR_REPONSE"] = None

    final_result_df = pd.DataFrame()

    for index, row in df.iterrows():
        current_timestamp = datetime.datetime.now()

        request_timestamp = current_timestamp.strftime("%Y-%m-%dT%H:%M:%S")
        first_name = row["FirstName"]
        print(first_name)
        source_system = "mCAS"
        requestor = "04"
        request_ref_number = get_random_id()
        customer_number = row["CustomerNumber"]
        state_code = get_state_master(row["State"])
        gender_code = get_gender_code(row["Gender"])
        address_type_code = get_address_type_code(row["AddressType"])
        residence_type_code = get_residence_type_code(row["ResidenceType"])
        last_name = row["LastName"]
        print(str(row["PhoneNumber"]))
        phone_number = str(row["PhoneNumber"]).strip()
        dob = str(row['DateOfBirth'])
        dob = datetime.datetime.strptime(str(dob),'%Y-%m-%d %H:%M:%S')
        dob = dob.strftime("%d%m%Y")
        print(dob)
        pan_id = row["IdentificationNumber"]
        requested_loan_amount = int(row["LoanAmountRequested"])
        active_address = row["ActiveAddress"]
        
        if active_address == 'TRUE':
            active_address = True
        else:
            active_address = False

        no_of_dependents = 0
        country_iso_code_1 = "IND"
        country_iso_code = "null"
        negative_country = "false"
        month_in_current_city = 0
        no_of_months_at_address = 0
        no_of_years_at_address = 0
        primary_address = "true"
        send_parcel = "false"
        years_in_current_city = 0
        zipcode = int(row["Zipcode"])
        phone_number_country_code = "IN"
        isd_code = 0
        number_type_code = "00"
        identification_details_country_code = "IND"
        identification_type_code = "01"
        salary_credit_in_icici = False
        existing_relationship = False
        loan_purpose = "50"
        loan_scheme = 0 
        loan_product = 0 
        reinitiate = "false"

        address_line_1 = row["AddressLine1"]
        if str(row["AddressLine2"]) != 'nan':
            address_line_2 = row["AddressLine2"]
        else:
            address_line_2 = ""

        if str(row["AddressLine3"]) != 'nan':
            address_line_3 = row["AddressLine3"]
        else:
            address_line_3 = ""
                   

        request_payload_json = {
            "CreditBureauGenericRequest": {
                "RequestTimestamp": f"{request_timestamp}",
                "SourceSystem": "mCAS",
                "Requestor": "04",
                "CreditBureauEnquiryRecord": {
                "RequestReferenceNumber": request_ref_number,
                "BureauCodes": "",
                "CustomerDetails": {
                    "CustomerNumber": customer_number,
                    "CustomerType": "",
                    "CustomerRole": "",
                    "PersonInfo": {
                    "CustomerCategory": {
                        "Code": ""
                    },
                    "DateOfBirth": f"{dob}",
                    "FirstName": f"{first_name}",
                    "Gender": {
                        "Code": f"{gender_code}"
                    },
                    "LastName": f"{last_name}",
                    "MaritalStatus": {
                        "Code": ""
                    },
                    "NoOfDependents": 0,
                    "Salutation": {
                        "Code": ""
                    }
                    },
                    "ContactInfo": {
                    "Addresses": {
                        "AccomodationType": {
                        "Code": ""
                        },
                        "ActiveAddress": active_address,
                        "AddressLine1": f"{address_line_1}",
                        "AddressLine2": f"{address_line_2}",
                        "AddressLine3": f"{address_line_3}",
                        "AddressType": {
                        "Code": f"{address_type_code}"
                        },
                        "City": {
                        "Code": 0
                        },
                        "Country": {
                        "CountryISOCode": "IND",
                        "NegativeCountry": False,
                        "Code": None
                        },
                        "LandMark": None,
                        "MonthsInCurrentCity": 0,
                        "NumberOfMonthsAtAddress": 0,
                        "NumberOfYearsAtAddress": 0,
                        "PrimaryAddress": True,
                        "ResidenceType": {
                        "Code": f"{residence_type_code}"
                        },
                        "SendParcel": False,
                        "State": {
                        "Code": f"{state_code}"
                        },
                        "YearsInCurrentCity": 0,
                        "Zipcode": zipcode
                    },
                    "PhoneNumbers": {
                        "CountryCode": "IN",
                        "IsdCode": 0,
                        "NumberType": {
                        "Code": "00"
                        },
                        "PhoneNumber": f"{phone_number}"
                    }
                    },
                    "IdentificationDetails": {
                    "Country": {
                        "CountryISOCode": None,
                        "NegativeCountry": False,
                        "Code": "IND"
                    },
                    "IdentificationNumber": f"{pan_id}",
                    "IdentificationType": {
                        "Code": "01"
                    }
                    },
                    "SalaryCreditInICICI": False,
                    "ExistingRelation": False
                },
                "ApplicationDetails": {
                    "LoanPurpose": {
                    "ValueKind": "50"
                    },
                    "LoanScheme": {
                    "ValueKind": 0
                    },
                    "LoanProduct": {
                    "ValueKind": 0
                    },
                    "ProductType": {
                    "Code": ""
                    },
                    "LoanAmountRequested": {
                    "ValueKind": requested_loan_amount
                    }
                },
                "ReInitiate": False
                }
            }
            }
    

        request_payload = json.dumps(request_payload_json)

        print("++++",request_payload)

        key = "RANDOM HEX KEY"

        encrypted_payload = encrypt_data(str(request_payload), key)

        try:
            response = api_call(encrypted_payload)
            decrypted_payload = decrypt_data(response,key)
            print("line 1092")
            print("DECRYPTED REPONSE:",decrypted_payload)
            print("line 1094")
            temp_result_df = convert_json_to_df(decrypted_payload)
            # temp_result_df = remove_duplicate_columns(temp_result_df)
            print("line 1097")
            writer = pd.ExcelWriter(f'{first_name}_{last_name}.xlsx', engine='xlsxwriter') 
            print("line 1099")
            temp_result_df.to_excel(writer, 'OVERALL DATA', index = False)
            print("line 1101")
            writer.save()
            print("line 1103")
            temp_result = pd.read_excel(f'{first_name}_{last_name}.xlsx',dtype=str)
            
            
            print("line 1105")
            os.remove(f'{first_name}_{last_name}.xlsx')
            
            print("line 1108")
            temp_result = convert_codes_to_value(temp_result)
            
            print("line 1109")
            payment_history_df = get_payment_history_data(temp_result)
            
            print("line 1114")
            if payment_history_df is not None:
                
                writer = pd.ExcelWriter(f'{first_name}_{last_name}_Payment_History.xlsx', engine='xlsxwriter')  
                
                payment_history_df.to_excel(writer, 'Sheet1', index = False)
               
                writer.save()
                
                payment_history_df = pd.read_excel(f'{first_name}_{last_name}_Payment_History.xlsx',dtype=str)
        
                os.remove(f'{first_name}_{last_name}_Payment_History.xlsx')
                payment_history_df = update_and_pivot(payment_history_df)
                payment_history_df_styled = payment_history_df.style.apply(highlight_condition_index_rows,axis=1)
    
    
                output_file_name = f'{first_name}_{last_name}_{current_date_time}.xlsx'
                writer = pd.ExcelWriter(output_file_name, engine='openpyxl')   
                
                temp_result.to_excel(writer, 'OVERALL DATA', index = False)
                payment_history_df_styled.to_excel(writer, 'PAYMENT DPD HISTORY', index = False)
                writer.save()
    
                #sheet 3 code goes here
                df_sheet_3 = main_sheet_3(output_file_name)
    
                df_sheet_3.to_excel(writer, 'Sheet 3', index = False)
                writer.save()
    
    
            else:
                print("line 1143")
                output_file_name = f'{first_name}_{last_name}_{current_date_time}.xlsx'
                print("line 1145")
                writer = pd.ExcelWriter(output_file_name, engine='openpyxl')   
                print("line 1147")
                temp_result.to_excel(writer, 'OVERALL DATA', index = False)
                print("line 1149")
                writer.save()
                print("line 1151")
    
            print("#### UPLOADING FILE TO SFTP LOCATION")
            upload_files_to_sftp(output_file_name,f"{output_folder_path}/{output_file_name}")
            print("line 1155")
    
    
                
                # s3.Bucket('sulb-finnone').upload_file(output_file_name, f'SCF_CIBIL_API /Backup/{output_file_name}')
        except Exception as e:
            print("ERROR OCCURRED:",e)
            df.at[index,"ERROR_REPONSE"] = str(e)
            

    df.to_excel(file,index=False)
    





        
        
def list_file_folder():
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=host,port=port,username=username,password=password)
    sftp = ssh_client.open_sftp()
    files = sftp.listdir(remote_file_path)
    sftp.close()
    ssh_client.close()

    return files

def upload_processed_and_delete_file_from_sftp(local_file_path,remote_file_path,sftp,source_file_path):
    upload_files_to_sftp(local_file_path,remote_file_path)
    sftp.remove(source_file_path)



def sftp_make_out_dir(file,sftp):
    folder_name = str(file).replace(".xlsx",f"_{current_date_time}")
    sftp.mkdir(f"{output_file_path}/{folder_name}")

    output_folder_path_get = f"{output_file_path}/{folder_name}"

    return output_folder_path_get



def main():
    file_list = list_file_folder()
    for file in file_list:
        print(f"Download file to local path:{file} from {remote_file_path}/{file}")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=host,port=port,username=username,password=password)
        sftp = ssh_client.open_sftp()
        # Dowloading file to local
        sftp.get(f"{remote_file_path}/{file}", f"{file}")

        # Create Directory for Each File to store the Output/resultant files
        folder_name_path = sftp_make_out_dir(file,sftp)
        
        #Code to Get the API Response and Transform into required Format
        print("######Code for processing the files##########")
        convert_json_to_etl(file,folder_name_path,sftp)

        # After File Processing Completed Add File to Processed Folder and delete file from Input Directory and 
        upload_processed_and_delete_file_from_sftp(f"{file}",f"{processed_file_path}/{file}",sftp,f"{remote_file_path}/{file}")
        sftp.close()
    

if __name__ == "__main__":
    main()