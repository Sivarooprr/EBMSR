from flask import Blueprint, render_template, redirect, request, flash, url_for
from flask_login import login_required, current_user
from . import db
from .models import Employee
#new imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import DES, ARC4
from Crypto.Random import get_random_bytes
import base64

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/employees')
@login_required
def employees():
    return render_template('employees.html', emp_list=get_all_employee_list())

@main.route('/add_employee')
@login_required
def add_employee():
    return render_template('add_employee.html')

@main.route('/delete_employee/<emp_id>')
@login_required
def delete_employee(emp_id):
    Employee.query.filter_by(E_ID=int(emp_id)).delete()
    db.session.commit()
    return redirect(url_for('main.employees'))

@main.route('/add_employee', methods=['POST'])
@login_required
def add_employee_post():
    name = request.form.get('name')
    user_id = request.form.get('user_id')
    department = request.form.get('department')
    salary = request.form.get('salary')
    password = request.form.get('password')
    access = request.form.get('access')

    if '' in [name,user_id,department,salary,password] or access == "0":
        flash('All fields are mandatory')
        return redirect(url_for('main.add_employee'))

    if access == "TS":         
        #AES-256
        new_emp = Employee(
                            E_Name=encrypt_aes_256(name),
                            E_UserID=encrypt_aes_256(user_id),
                            E_Department=encrypt_aes_256(department),
                            E_Salary=encrypt_aes_256(salary),
                            E_Password=encrypt_aes_256(password),
                            E_TC=access
                            )

    elif access == "S":
        #DES
        new_emp = Employee(
                            E_Name=encrypt_des(name),
                            E_UserID=encrypt_des(user_id),
                            E_Department=encrypt_des(department),
                            E_Salary=encrypt_des(salary),
                            E_Password=encrypt_des(password),
                            E_TC=access
                            )
    else:
        #RC4
        new_emp = Employee(
                            E_Name=encrypt_rc4(name),
                            E_UserID=encrypt_rc4(user_id),
                            E_Department=encrypt_rc4(department),
                            E_Salary=encrypt_rc4(salary),
                            E_Password=encrypt_rc4(password),
                            E_TC=access
                            )
    db.session.add(new_emp)
    db.session.commit()

    return redirect(url_for('main.employees'))


def get_all_employee_list():
    emp_list = Employee.query.all()
    new_list = []
    for emp in emp_list:
        if emp.E_TC == "TS":
            new_list.append(
                {
                    "E_ID": emp.E_ID,
                    "E_Name": decrypt_aes_256(emp.E_Name),
                    "E_UserID": decrypt_aes_256(emp.E_UserID),
                    "E_Department": decrypt_aes_256(emp.E_Department),
                    "E_Salary": decrypt_aes_256(emp.E_Salary),
                    "E_TC": emp.E_TC
                }
            )
        elif emp.E_TC == "S":
            new_list.append(
                {
                    "E_ID": emp.E_ID,
                    "E_Name": decrypt_des(emp.E_Name),
                    "E_UserID": decrypt_des(emp.E_UserID),
                    "E_Department": decrypt_des(emp.E_Department),
                    "E_Salary": decrypt_des(emp.E_Salary),
                    "E_TC": emp.E_TC
                }
            )
        else:
            new_list.append(
                {
                    "E_ID": emp.E_ID,
                    "E_Name": decrypt_rc4(emp.E_Name),
                    "E_UserID": decrypt_rc4(emp.E_UserID),
                    "E_Department": decrypt_rc4(emp.E_Department),
                    "E_Salary": decrypt_rc4(emp.E_Salary),
                    "E_TC": emp.E_TC
                }
            )
            
    return new_list

#new variables&functions
aes_key = "myaeskey123456789012345678901234" 
des_key = "mydeskey" 
rc4_key = "myrc4key"
def pad(data, block_size):
    pad_len = block_size - len(data) % block_size
    padding = bytes([pad_len] * pad_len)
    return data + padding

def unpad(data, block_size):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_aes_256(st, key=aes_key):
    # do the encryption

    key = key[:32]  # Ensure key is 256 bits (32 bytes)
    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(st.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    st= base64.b64encode(encrypted_data).decode()
    return st

def decrypt_aes_256(st, key=aes_key):
    # do the decryption

    key = key[:32]  # Ensure key is 256 bits (32 bytes)
    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(base64.b64decode(st)) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    st = unpadded_data.decode() 
    return st

def encrypt_des(st, key=des_key):
    # do the encryption
    key = key[:8]  # Ensure key is 64 bits (8 bytes)
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    padded_data = pad(st.encode(), DES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    st= base64.b64encode(encrypted_data).decode()
    return st

def decrypt_des(st, key=des_key):
    # do the decryption
    key = key[:8]  # Ensure key is 64 bits (8 bytes)
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    decrypted_data = cipher.decrypt(base64.b64decode(st))
    unpadded_data = unpad(decrypted_data, DES.block_size)
    #return unpadded_data.decode()
    st = unpadded_data.decode()
    return st

def encrypt_rc4(st, key=rc4_key):
    # do the encryption
    cipher = ARC4.new(key.encode())
    encrypted_data = cipher.encrypt(st.encode())
    st= base64.b64encode(encrypted_data).decode()
    return st

def decrypt_rc4(st, key=rc4_key):
    # do the decryption
    cipher = ARC4.new(key.encode())
    decrypted_data = cipher.decrypt(base64.b64decode(st))
    st= decrypted_data.decode()
    return st
