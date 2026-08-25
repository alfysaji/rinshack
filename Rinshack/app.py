import re
from flask import Flask, render_template, request, make_response, redirect, url_for, flash, send_from_directory, session

app = Flask(__name__, static_folder='templates', static_url_path='/templates')
app.secret_key = 'super_secret_ctf_key'

# Separate Flask's internal login session cookie from CTF challenge cookies
app.config['SESSION_COOKIE_NAME'] = 'flask_auth_session'

# Base64 encoded value of "RINS_4{VErUM_3999_m@thrAm}"
FLAG_COOKIE_VALUE = "UklOU180e1ZFclVNXzM5OTlfbUB0aHJBbX0="

def set_flag_cookie(response):
    """Utility function to attach the CTF flag cookie strictly to /product191."""
    response.set_cookie(
        'session_id', 
        FLAG_COOKIE_VALUE, 
        httponly=False,
        samesite='Lax',
        path='/product191'  # <-- Browser natively restricts this cookie ONLY to /product191
    )
    return response

# ==========================================
# TEXT FILE ROUTES
# ==========================================

@app.route('/robots.txt')
def serve_robots():
    return send_from_directory(app.template_folder, 'robots.txt', mimetype='text/plain')

@app.route('/S3cr3T5.txt')
@app.route('/S3cr3T5')
def serve_secrets():
    return send_from_directory(app.template_folder, 'S3cr3T5.txt', mimetype='text/plain')

# ==========================================
# GENERAL ROUTES
# ==========================================

@app.route('/')
def home():
    return redirect(url_for('index'))

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/product1')
def product1_page():
    return render_template('product1.html')

@app.route('/product2', methods=['GET', 'POST'])
def product2():
    flag = None
    if request.method == 'POST':
        submitted_price = request.form.get('price', '')
        
        try:
            if float(submitted_price) == 0:
                flag = "RINS_7{kIdIll4M_b1r1yAN1_SpoT}"
            else:
                flash("Transaction Failed: Insufficient funds to pay " + str(submitted_price) + " ETH!")
        except ValueError:
            flash("Invalid price format submitted!")

    return render_template('product2.html', flag=flag)

@app.route('/product3')
def product3_page():
    return render_template('product3.html')

@app.route('/product191')
def product191_page():
    """Only product 191 attaches the flag cookie."""
    resp = make_response(render_template('product191.html'))
    return set_flag_cookie(resp)

# ==========================================
# AUTHENTICATION & ADMIN ROUTES
# ==========================================

@app.route('/one_first_vish')
def one_first_vish():
    # Protect route from unauthenticated access
    if not session.get('authenticated'):
        flash('Access Denied: You must log in as agent VIZ to view this page!', 'danger')
        return redirect(url_for('signin'))
        
    # Render the dossier page for agent one_first_vish
    return render_template('one_first_vish.html', endpoints=['logout'])

@app.route('/signin', methods=['GET', 'POST'])
@app.route('/signup', methods=['GET', 'POST'])
def signin():
    show_ape_popup = False

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # 1. Target Account: @one_first_vish / sunshine
        if username == 'one_first_vish' and password == 'sunshine':
            session['authenticated'] = True
            session['user'] = 'one_first_vish'
            flash('Welcome, Agent VIZ!', 'success')
            return redirect(url_for('one_first_vish'))

        # 2. SQL Injection pattern matcher
        sqli_patterns = [
            r"'\s*or\s*'?\d+'?\s*=\s*'?\d+",   # ' OR '1'='1
            r"'\s*or\s*1\s*=\s*1",             # ' OR 1=1
            r"admin'\s*--",                    # admin' --
            r"'\s*or\s*''='",                  # ' OR ''='
            r"--",                             # Comment syntax
        ]
        
        combined_input = f"{username} {password}".lower()
        is_sqli = any(re.search(pattern, combined_input, re.IGNORECASE) for pattern in sqli_patterns)

        # 3. Admin Login or SQL Injection Bypass
        if (username == 'admin' and password == 'admin123') or is_sqli:
            session['authenticated'] = True
            session['user'] = 'admin'
            flash('Welcome Admin!', 'success')
            return redirect(url_for('admin_page'))

        # 4. Failed Login -> Trigger Flash & Ape Popup
        flash('Invalid username or password!', 'danger')
        show_ape_popup = True

    return render_template('signup.html', show_ape_popup=show_ape_popup)

@app.route('/admin')
def admin_page():
    if not session.get('authenticated'):
        flash('Access Denied: You must log in as Administrator to view this page!', 'danger')
        return redirect(url_for('signin'))

    flag = "RINS_3{pod@_ONnu}"
    auth_type = "Administrator Session"

    return render_template('admin.html', flag=flag, auth_type=auth_type)

@app.route('/Ch@!!3nge', methods=['GET', 'POST'])
def challenge():
    flag = None
    error = None

    if request.method == 'POST':
        # Retrieve parameters from POST payload
        ans1 = request.form.get('ans1', '').strip()
        ans2 = request.form.get('ans2', '').strip()
        ans3 = request.form.get('ans3', '').strip()  # Intercepted via Burp Suite

        # Math verification: Q1=27, Q2=56, Q3=58
        if not ans3:
            error = "⚠️ Security Check Failed: Parameter 'ans3' missing! The client-side controls prevented submission."
        elif ans1 == '27' and ans2 == '56' and ans3 == '58':
            # SUCCESS FLAG DISPLAY
            flag = "RINS_6{Fe3$_Du3_AY!tondu}"
        else:
            error = "❌ Incorrect calculation detected! Check your values and try again."

    return render_template('Ch@!!3nge.html', flag=flag, error=error)

@app.route('/logout')
def logout():
    session.clear()
    flash('Successfully logged out.', 'info')
    return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)