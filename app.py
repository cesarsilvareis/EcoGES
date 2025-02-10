#!/usr/bin/python3
from cryptography.hazmat.primitives import padding as sym_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

import os
import psycopg2
import psycopg2.extras
import ssl

## App configs
HOST = "192.168.1.1"
PORT = 3000
CERT_PATH = "keys/server.crt"
KEY_PATH = "keys/server.key"

DEBUG = True

#### SGBD configs
DB_HOST = "192.168.2.4"
DB_USER = "appserver"
DB_PORT = 5432
DB_DATABASE = "ecogesdb"
DB_PASSWORD = "app-dees"
DB_CONNECTION_STRING = "host=%s port=%d dbname=%s user=%s password=%s" % (
    DB_HOST,
    DB_PORT,
    DB_DATABASE,
    DB_USER,
    DB_PASSWORD,
)

USER_SESSION_LIFETIME_MIN = 2
ADMIN_NUMBER = 1

DEPARTMENTS = {
    "account": 1,
    "accountability": 2,
    "marketing": 3
}

class CipherMasMelhor:
    def __init__(self):
        self.algorithm = algorithms.AES256
        self.mode = modes.CBC
        self.padding = sym_padding.PKCS7

        key = os.urandom(self.algorithm.key_size // 8)
        iv = os.urandom(self.algorithm.block_size // 8)

        self.algorithm = self.algorithm(key)
        self.mode = self.mode(iv)
        self.cipher = Cipher(self.algorithm, self.mode)

        self.padding = self.padding(self.algorithm.block_size)

    def encrypt(self, msg: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        padder = self.padding.padder()

        # Add padding
        data = self.process(padder, msg)
        # Encrypt
        data = self.process(encryptor, data)

        return data

    def decrypt(self, msg: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        unpadder = self.padding.unpadder()

        # Decrypt
        data = self.process(decryptor, msg)
        # Remove padding
        data = self.process(unpadder, data)

        return data

    def process(self, context, msg: bytes):
        return context.update(msg) + context.finalize()


###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###             AUX  FUNCS             ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###


# this is just a dummy, ideally this function should ask the department for its public key
def get_dept_key(dept):
    with open(f"./keys/{dept}/{dept}_pub.key", "rb") as f:
        return serialization.load_pem_public_key(f.read())

# storing each department secret key encripted with its public key on DB
def add_key_to_db(dept):
    conn = psycopg2.connect(DB_CONNECTION_STRING)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    query = """
            INSERT INTO secret_key
            VALUES (%s, %s)
            ;"""

    id = DEPARTMENTS[dept]
    kek = app.config["DEPT_KEYS"][dept]["public"]
    key = app.config["DEPT_KEYS"][dept]["secret"].algorithm.key
    encrypted_key = kek.encrypt(key, asym_padding.PKCS1v15())
    data = (id, encrypted_key)

    cursor.execute(query, data)

    cursor.close()

    conn.commit()
    conn.close()

# This function is used to add a dummy admin to the site, use it only for testing
def add_default_admin():
    conn = psycopg2.connect(DB_CONNECTION_STRING)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Insert client
    query = """
            INSERT INTO client
            VALUES (DEFAULT, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            ;"""

    data = encrypt_data(
        nada = [
            "admin",
            "admin@admin.admin"
        ],
        account = [
            generate_password_hash("123456", method="sha256"),
            ADMIN_NUMBER
        ],
        accountability = [
            "Bank1"
        ],
        marketing = [
            "Disneylândia",
            "999-999-999"
        ]
    )

    cursor.execute(query, data)

    user_id = cursor.fetchone()[0]

    # Insert monthly invoice
    query = """
            INSERT INTO monthly_invoice
            VALUES (%s, %s, %s, %s, %s)
            ;"""

    data = encrypt_data(
        nada = [
            user_id,
            datetime.now().month,
            0
        ],
        accountability = [
            int(os.urandom(1) >= b"\x80"),
            0.01
        ]
    )

    cursor.execute(query, data)

    cursor.close()

    conn.commit()
    conn.close()


###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###      ENCRYPTION / DECRYPTION       ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###

def encrypt_data(**dept_dict):
    res = []
    for dept in dept_dict:
        data_list = dept_dict[dept]
        if dept in app.config["DEPT_KEYS"]:
            cipher = app.config["DEPT_KEYS"][dept]["secret"]
            data_list = map(lambda x: cipher.encrypt(str(x).encode("utf-8")), data_list)

        res += data_list

    return res

def decrypt_data(**dept_dict):
    res = []
    for dept in dept_dict:
        data_list = dept_dict[dept]
        if dept in app.config["DEPT_KEYS"]:
            data_list = map(lambda x: x.tobytes() if type(x) is memoryview else x, data_list)
            cipher = app.config["DEPT_KEYS"][dept]["secret"]
            data_list = map(lambda x: cipher.decrypt(x).decode("utf-8"), data_list)

        res += data_list

    return res


###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###             App  configs           ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###

app = Flask(__name__)
with open(KEY_PATH, "r") as f:
    app.config["SECRET_KEY"] = f.read()
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=USER_SESSION_LIFETIME_MIN)

app.config["DEPT_KEYS"] = dict()
for dept in DEPARTMENTS:
    app.config["DEPT_KEYS"][dept] = {
        "public": get_dept_key(dept),
        "secret": CipherMasMelhor()
    }
    add_key_to_db(dept)

if DEBUG:
    add_default_admin()

###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###           AUTHENTICATION           ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###

@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        dbConn = None
        cursor = None
        try:

            username = request.form.get("username")
            email = request.form.get("email")
            
            password1 = request.form.get("password1")
            password2 = request.form.get("password2")
            
            bank_account_id = request.form.get("bank_account_id")
           
            address = request.form.get("address")
            phone_number = request.form.get("phone_number")

            dbConn = psycopg2.connect(DB_CONNECTION_STRING)
            cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            query = """
                    SELECT * FROM client
                    WHERE name = %s
                    ;"""
            cursor.execute(query, (username, ))

            user = cursor.fetchone()
            if user:
                flash("User already exists.", category="error")
            elif len(username) < 3:
                flash("Username must have 3 or more characters.", category="error")
            elif len(email) < 5:
                flash("Email must have 5 or more characters.", category="error")
            elif len(password1) < 6:
                flash("Password must have 6 or more characters.", category="error")
            elif password1 != password2:
                flash("Passwords don't match.", category="error")
            else:
                # client: (id), name, email, pass, perms, bank_account_id, address, phone_number
                query = """
                        INSERT INTO client VALUES (DEFAULT, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                        ;"""
                data = encrypt_data(
                    nada = [
                        username,
                        email
                    ],
                    account = [
                        generate_password_hash(password1, method="sha256"),
                        2
                    ],
                    accountability = [
                        bank_account_id
                    ],
                    marketing = [
                        address,
                        phone_number
                    ]
                )
                cursor.execute(query, data)

                user_id = cursor.fetchone()[0]

                query = """
                        INSERT INTO monthly_invoice
                        VALUES (%s, %s, %s, %s, %s)
                        ;"""

                data = encrypt_data(
                    nada = [
                        user_id,
                        datetime.now().month,
                        0
                    ],
                    accountability = [
                        int(os.urandom(1) >= b"\x80"),
                        0.01
                    ]
                )
                cursor.execute(query, data)

                flash("Account created!", category="success")

                return redirect(url_for("login"))

        except Exception as e:
            if dbConn: dbConn.rollback()

            return render_template("error.html", error_message=str(e))
        finally:
            if cursor: cursor.close()
            if dbConn:
                dbConn.commit()
                dbConn.close()

    return render_template("sign_up.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        dbConn = None
        cursor = None
        try:
            dbConn = psycopg2.connect(DB_CONNECTION_STRING)
            cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            username = request.form.get("username")
            password = request.form.get("password")

            query = """
                    SELECT * FROM client
                    WHERE name = %s
                    ;"""
            cursor.execute(query, (username, ))

            user = cursor.fetchone()
            user = decrypt_data(
                nada = user[0:3],
                account = user[3:5],
                accountability = user[5:6],
                marketing = user[6:]
            )

            error_message = "Wrong username/password, please try again."
            if user:
                if check_password_hash(user[3], password):
                    flash("Logged in successfully!", category="success")

                    session["active"] = True
                    session["is_admin"] = int(user[4], 10) == ADMIN_NUMBER
                    session["user_id"] = user[0]
                    session["username"] = user[1]

                    session.permanent = True

                    return redirect(url_for("home"))
                else:
                    flash(error_message, category="error")
            else:
                flash(error_message, category="error")

        except Exception as e:
            if dbConn: dbConn.rollback()

            return render_template("error.html", error_message=str(e))
        finally:
            if cursor: cursor.close()
            if dbConn:
                dbConn.commit()
                dbConn.close()

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("active", None)
    session.pop("user_id", None)
    session.pop("username", None)

    return redirect(url_for("login"))


###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###              HOMEPAGE              ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###

@app.route("/")
def home():
    try:
        if "active" not in session:
            return redirect(url_for("login"))

        return render_template("index.html")
    except Exception as e:
        return render_template("error.html", error_message=str(e))


###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###       AUXILIARY  FUNCTIONS         ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###

def update_uptimes(cursor, user_id, table, id_i = 0, uptime_i = 3, active_i = 4, last_check_i = 5):
    if cursor.rowcount == 0: return False
    cursor.scroll(0, mode="absolute")

    uptimes = []
    for entry in cursor:
        uptime = entry[uptime_i]
        if entry[active_i]:
            last_check = entry[last_check_i]
            uptime += datetime.now() - last_check
            uptimes.append({"id": entry[id_i], "uptime": uptime})

    for uptime in uptimes:
        query = f"UPDATE {table}" + """
                SET
                    uptime = %s,
                    last_check = %s
                WHERE client_id = %s
                    AND id = %s
                ;"""
        cursor.execute(query, (uptime["uptime"], datetime.now(), user_id, uptime["id"]))

def update_energy_produced(cursor, user_id):
    if cursor.rowcount == 0: return False
    cursor.scroll(0, mode="absolute")

    stuffs = []
    for panel in cursor:
        energy = panel[3]
        production_rate = panel[2]
        if panel[5]:
            last_check = panel[6]
            uptime = datetime.now() - last_check
            energy += uptime.seconds * production_rate
            uptime += panel[4]
            stuffs.append({"id": panel[0], "energy": energy, "uptime": uptime})

    for stuff in stuffs:
        query = """
                UPDATE solar_panel SET
                    energy_produced = %s,
                    uptime = %s,
                    last_check = %s
                WHERE client_id = %s
                    AND id = %s
                ;"""
        cursor.execute(query, (stuff["energy"], stuff["uptime"], datetime.now(), user_id, stuff["id"]))

def update_appliances(cursor, user_id):
    query = """
            SELECT * FROM household_appliance
            WHERE client_id = %s
            ;"""
    cursor.execute(query, (user_id,))
    return update_uptimes(cursor, user_id, "household_appliance")

def update_panels(cursor, user_id):
    query = """
            SELECT * FROM solar_panel
            WHERE client_id = %s
            ;"""
    cursor.execute(query, (user_id,))
    return update_energy_produced(cursor, user_id)

###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###       HOUSEHOLD  APPLIANCES        ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###

@app.route("/appliances", methods = ["GET"])
def check_household_appliances():
    if "active" not in session:
        return redirect(url_for("login"))

    dbConn = None
    cursor = None
    user_id = session["user_id"]
    try:
        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        update_appliances(cursor, user_id)

        query = """
                SELECT * FROM household_appliance
                WHERE client_id = %s
                ORDER BY id
                ;"""
        cursor.execute(query, (user_id,))

        return render_template("household_appliances.html", appliances=cursor)
    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        if cursor: cursor.close()
        if dbConn:
            dbConn.commit()
            dbConn.close()

    # Should never get here, just for safety
    print("How did we get here??? check_appliance bug/error")
    return redirect("/")

@app.route("/appliances/insert" , methods = ["GET", "POST"])
def add_appliance():
        if request.method == "GET":
            return redirect("/appliances")
        if "active" not in session:
            return redirect(url_for("login"))

        dbConn = None
        cursor = None
        user_id = session["user_id"]
        try:
            appliance_id = request.form["appliance_id"]
            appliance_name = request.form["appliance_name"]
            appliance_energy_consumption = request.form["appliance_consumption_rate"]
            appliance_uptime = "0"
            appliance_active = "appliance_active" in request.form

            dbConn = psycopg2.connect(DB_CONNECTION_STRING)
            cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            query = """
                    INSERT INTO household_appliance VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ;"""

            cursor.execute(query, (appliance_id, appliance_name, appliance_energy_consumption, appliance_uptime, appliance_active, datetime.now(), user_id))
            flash(f"Appliance {appliance_name} with id {appliance_id} added successfully", category="success")

            return redirect("/appliances")

        except Exception as e:
            if dbConn: dbConn.rollback()

            return render_template("error.html", error_message=(e))
        finally:
            if cursor: cursor.close()
            if dbConn:
                dbConn.commit()
                dbConn.close()

        # Should never get here, just for safety
        print("How did we get here??? add_appliance bug/error")
        return redirect("/")

@app.route("/appliances/update" , methods = ["GET", "POST"])
def update_appliance():
    if request.method == "GET":
        return redirect("/appliances")
    if "active" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return redirect("/appliances")

    dbConn = None
    cursor = None
    user_id = session["user_id"]
    try:
        appliance_id = request.form["appliance_id"]
        appliance_name = request.form["appliance_name"]
        appliance_energy_consumption = request.form["appliance_energy_consumption"]
        appliance_active = "appliance_active" in request.form

        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = """
                UPDATE household_appliance
                SET
                    name = %s,
                    energy_consumption = %s,
                    active = %s
                WHERE id = %s AND client_id = %s
                ;"""
        cursor.execute(query, (appliance_name, appliance_energy_consumption, appliance_active, appliance_id, user_id))

        update_appliances(cursor, user_id)

        flash(f"Appliance {appliance_name} with id {appliance_id} updated successfully", category="success")

        return redirect("/appliances")
    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        if cursor: cursor.close()
        if dbConn:
            dbConn.commit()
            dbConn.close()

    # Should never get here, just for safety
    print("How did we get here??? update_appliance bug/error")
    return redirect("/")

@app.route("/appliances/delete", methods = ["GET", "POST"])
def delete_appliance():
    if request.method == "GET":
        return redirect("/appliances")
    if "active" not in session:
        return redirect(url_for("login"))

    dbConn = None
    cursor = None
    try:
        appliance_id = request.form["appliance_id"]
        appliance_name = request.form["appliance_name"]

        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = """
                DELETE FROM household_appliance
                WHERE id = %s AND client_id = %s
                ;"""
        cursor.execute(query, (appliance_id, session["user_id"]))
        flash(f"Appliance '{appliance_name}' with id {appliance_id} deleted successfully", category="success")

        return redirect("/appliances")
    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        if cursor: cursor.close()
        if dbConn:
            dbConn.commit()
            dbConn.close()

    # Should never get here, just for safety
    print("How did we get here??? delete_appliance bug/error")
    return redirect("/")


###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###           SOLAR  PANELS            ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###

@app.route("/panels", methods = ["GET"])
def check_solar_panels():
    if "active" not in session:
        return redirect(url_for("login"))

    dbConn = None
    cursor = None
    user_id = session["user_id"]
    try:
        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        update_panels(cursor, user_id)

        query = """
                SELECT * FROM solar_panel
                WHERE client_id = %s
                ORDER BY id
                ;"""
        cursor.execute(query, (user_id,))

        return render_template("solar_panels.html", panels=cursor)
    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        if cursor: cursor.close()
        if dbConn:
            dbConn.commit()
            dbConn.close()

    # Should never get here, just for safety
    print("How did we get here??? add_appliance bug/error")
    return redirect("/")

@app.route("/panels/insert" , methods = ["GET", "POST"])
def add_panel():
    if request.method == "GET":
        return redirect("/panels")
    if "active" not in session:
        return redirect(url_for("login"))

    dbConn = None
    cursor = None
    user_id = session["user_id"]
    try:
        panel_id = request.form["panel_id"]
        panel_name = request.form["panel_name"]
        panel_production_rate = request.form["panel_production_rate"]
        panel_energy_produced = 0.0
        panel_uptime = "0"
        panel_active = "panel_active" in request.form

        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = """
                INSERT INTO solar_panel VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ;"""
        cursor.execute(query, (panel_id, panel_name, panel_production_rate, panel_energy_produced, panel_uptime, panel_active, "now", user_id))
        flash(f"Solar panel {panel_name} with id {panel_id} added successfully", category="success")

        return redirect("/panels")

    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        dbConn.commit()
        cursor.close()
        dbConn.close()

    # Should never get here, just for safety
    print("How did we get here??? add_panel bug/error")
    return redirect("/")

@app.route("/panels/update" , methods = ["GET", "POST"])
def update_panel():
    if request.method == "GET":
        return redirect("/panels")
    if "active" not in session:
        return redirect(url_for("login"))

    dbConn = None
    cursor = None
    user_id = session["user_id"]
    try:
        panel_id = request.form["panel_id"]
        panel_name = request.form["panel_name"]
        panel_production_rate = request.form["panel_production_rate"]
        panel_active = "panel_active" in request.form
        
        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = """
                UPDATE solar_panel
                SET
                    name = %s,
                    energy_production_rate = %s,
                    active = %s
                WHERE id = %s AND client_id = %s
                ;"""
        cursor.execute(query, (panel_name, panel_production_rate, panel_active, panel_id, user_id))

        update_panels(cursor, user_id)

        flash(f"Solar panel with id {panel_id} updated successfully", category="success")
        return redirect("/panels")
    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        if cursor: cursor.close()
        if dbConn:
            dbConn.commit()
            dbConn.close()

    # Should never get here, just for safety
    print("How did we get here??? update_panel bug/error")
    return redirect("/")

@app.route("/panels/delete", methods = ["GET", "POST"])
def delete_panel():
    if request.method == "GET":
        return redirect("/panels")
    if "active" not in session:
        return redirect(url_for("login"))

    dbConn = None
    cursor = None
    user_id = session["user_id"]
    try:
        panel_id = request.form["panel_id"]
        panel_name = request.form["panel_name"]

        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = """
                DELETE FROM solar_panel
                WHERE id = %s AND client_id = %s
                ;"""
        cursor.execute(query, (panel_id, user_id))
        flash(f"Solar panel '{panel_name}' with id {panel_id} deleted successfully", category="success")

        return redirect("/panels")
    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        if cursor: cursor.close()
        if dbConn:
            dbConn.commit()
            dbConn.close()

    # Should never get here, just for safety
    print("How did we get here??? delete_panel bug/error")
    return redirect("/")


###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###
###         MONTHLY  INVOICE           ###
###-#-#-#-#-#-#-#-#--#-#-#-#-#-#-#-#-#-###

@app.route("/invoice")
def check_monthly_invoice():
    if "active" not in session:
        return redirect(url_for("login"))
        
    dbConn = None
    cursor = None
    user_id = session['user_id']
    try:
        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query = """
                SELECT * FROM monthly_invoice
                WHERE id = %s
                ORDER BY month
                ;"""
        cursor.execute(query, (user_id,))

        monthly_invoices_info = cursor.fetchone() or []
        bank_account = None

        if session["is_admin"]:
            monthly_invoices_info = decrypt_data(
                nada = monthly_invoices_info[0:3],
                accountability = monthly_invoices_info[3:]
            )
            query = """
                    SELECT bank_account_id FROM client
                    WHERE id = %s
                    ;"""
            cursor.execute(query, (user_id, ))
            bank_account = decrypt_data(accountability = cursor.fetchone()[0:1])
            bank_account = bank_account[0]

        return render_template("monthly_invoice.html", bank_account=bank_account, monthly_invoices_info=monthly_invoices_info)
    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        if cursor: cursor.close()
        if dbConn:
            dbConn.commit()
            dbConn.close()


@app.route("/invoice/update" , methods = ["GET", "POST"])
def update_monthly_invoice():
    if request.method == "GET":
        return redirect("/invoice")
    if "active" not in session:
        return redirect(url_for("login"))

    dbConn = None
    cursor = None
    user_id = session["user_id"]
    try:
        dbConn = psycopg2.connect(DB_CONNECTION_STRING)
        cursor = dbConn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        monthly_invoice_plan = request.form.get("monthly_invoice_plan")
        if not monthly_invoice_plan:
            flash(f"Monthly Invoice update error: plan not provided!")
            return redirect("/invoice")

        bank_account_id = request.form.get("bank_account_id")
        if not bank_account_id:
            flash(f"Monthly Invoice update error: bank account id not provided!")
            return redirect("/invoice")

        query = """
                UPDATE monthly_invoice SET plan = %s
                WHERE id = %s
                ;"""
        monthly_invoice_plan = encrypt_data(
            accountability = [monthly_invoice_plan]
        ) + [user_id]

        cursor.execute(query, monthly_invoice_plan)

        query = """
                UPDATE client SET bank_account_id = %s
                WHERE id = %s
                ;"""

        bank_account_id = encrypt_data(
            accountability = [bank_account_id]
        ) + [user_id]

        cursor.execute(query, bank_account_id)
        flash(f"Monthly Invoice updated successfully", category="success")

        return redirect("/invoice")
    except Exception as e:
        if dbConn: dbConn.rollback()

        return render_template("error.html", error_message=str(e))
    finally:
        if cursor: cursor.close()
        if dbConn:
            dbConn.commit()
            dbConn.close()


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_PATH, KEY_PATH)
    app.run(HOST, PORT, ssl_context=context, debug=False)
