import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from sqlalchemy.sql.expression import false, true, update
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    symbols = db.execute("SELECT symbol, quantity from holdings WHERE user_id = ? ORDER BY quantity", session["user_id"])
    total_value = 0
    stock = {}
    for s in symbols:
        symbol, shares = s["symbol"], s["quantity"]
        stock[symbol] = stock.setdefault(symbol, 0) + shares
    for symbol, shares in stock.items():
        quote = lookup(symbol)
        price = quote["price"]
        company = quote["name"]
        stock_value = shares * price
        total_value += stock_value
        stock[symbol] = (company, shares, usd(price), usd(stock_value))
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash']
    total_value += cash
    return render_template("index.html", stock=stock, cash=usd(cash), gtotal=usd(total_value))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # return normal buy page via get
    if request.method == "GET":
        return render_template("buy.html")

    # when user submits form to buy
    if request.method == "POST":
        symbol = request.form.get("symbol")

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Shares must be integer", 400)

        if not symbol or not lookup(symbol):
            return apology("Enter valid stock symbol", 400)
        if not shares:
            return apology("Enter valid stock quantity", 400)
        if shares <= 0:
            return apology("Enter valid stock quantity", 400)
        else:
            quote = lookup(symbol)
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash']
            quantity = shares
            amount = quantity * quote["price"]
            if amount <= cash:
                balance = cash - amount
                db.execute("INSERT INTO transactions (user_id, symbol, price, datetime, company, type, quantity) VALUES (?, ?, ?, datetime('now'), ?, 'buy', ?)",
                           session["user_id"], symbol, quote["price"], quote["name"], shares)
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])
                stock_exists = db.execute("SELECT quantity FROM holdings WHERE company = ? AND user_id = ?",
                                          quote["name"], session["user_id"])
                if not stock_exists:
                    db.execute("INSERT INTO holdings (user_id, company, quantity, symbol) VALUES (?, ?, ?, ?)",
                               session["user_id"], quote["name"], quantity, quote["symbol"])
                else:
                    tot_quan = stock_exists[0]['quantity'] + quantity
                    db.execute("UPDATE holdings SET quantity = ? WHERE company = ? AND user_id = ?",
                               tot_quan, quote["name"], session["user_id"])

                return redirect("/")
            if amount >= cash:
                return apology("Not enough balance!", 666)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    if request.method == "GET":
        data = {}
        transactions = db.execute("SELECT trans_id, type, company, symbol, quantity, price, datetime FROM transactions WHERE user_id = ? ORDER BY trans_id DESC",
                                  session["user_id"])
        for t in transactions:
            type, company, symbol = t["type"], t["company"], t["symbol"].upper()
            quantity, price, datetime = t["quantity"], t["price"], t["datetime"]
            id = t["trans_id"]
            data[id] = (type, company, symbol, quantity, price, datetime)
        return render_template("history.html", data=data)
    else:
        return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if not quote:
            return apology("Enter valid symbol", 400)
        else:
            return render_template("quoted.html", quote=quote)
    else:
        return redirect("/quote")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # retrieve db of all usernames
        usernames = db.execute("SELECT username FROM users")

        # check username if empty or already existant, render apology
        username = request.form.get("username")
        usercheck = len(db.execute("SELECT username from users where username = ?", username))
        if not username:
            return apology("Missing Username", 400)
        if usercheck > 0:
            return apology("Username already exists", 400)

        # check if password input is blank or passwords don't match, render apology
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation:
            return apology("Fill in all inputs!", 400)
        if password != confirmation:
            return apology("Passwords don't match!", 400)

         # insert new user into db, use generate_password_hash
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                       username, generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))

        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/password", methods=["GET", "POST"])
@login_required
def changepw():
    """Allow user to change password"""

    if request.method == "GET":
        return render_template("change_pw.html")

    if request.method == "POST":
        # check username if empty or already existant, render apology
        old = request.form.get("oldpw")
        oldpwcheck = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]['hash']
        if check_password_hash(oldpwcheck, old) == False:
            return apology("Incorrect Password", 403)
        if check_password_hash(oldpwcheck, old) == True:
            new = request.form.get("newpw")
            conf = request.form.get("confirmation")
            if not new or not conf:
                return apology("Missing passwords", 404)
            elif new != conf:
                return apology("New Passwords don't match", 400)
            else:
                newpw = generate_password_hash(new, method='pbkdf2:sha256', salt_length=8)
                db.execute("UPDATE users SET hash = ? WHERE id = ?", newpw, session["user_id"])

        return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        symbols = db.execute("SELECT symbol FROM holdings WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", symbols=symbols)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = float(request.form.get("shares"))
        if not symbol:
            return apology("Choose a Stock's symbol", 400)
        if not shares:
            return apology("Enter valid stock quantity", 400)

        q_available = db.execute("SELECT quantity FROM holdings WHERE symbol = ? AND user_id = ?",
                                 symbol, session["user_id"])[0]['quantity']
        if (shares % 1 != 0) or shares <= 0:
            return apology("Enter valid stock quantity", 400)
        if shares > q_available:
            return apology("Not enough shares!", 400)

        else:
            quote = lookup(symbol)
            shares = int(request.form.get("shares"))
            q_left = q_available - shares
            cost = shares * quote["price"]
            bal = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash']
            new_bal = bal + cost
            if q_left != 0:
                db.execute("UPDATE users SET cash = ? WHERE id = ?", new_bal, session["user_id"])
                db.execute("UPDATE holdings SET quantity = ? WHERE user_id = ? AND symbol = ?",
                           q_left, session["user_id"], symbol)
                db.execute("INSERT INTO transactions (user_id, company, symbol, price, quantity, type, datetime) VALUES (?, ?, ?, ?, ?, 'sell', datetime('now'))",
                           session["user_id"], quote["name"], symbol, quote["price"], shares)

            if q_left == 0:
                db.execute("UPDATE users SET cash = ? WHERE id = ?", new_bal, session["user_id"])
                db.execute("INSERT INTO transactions (user_id, company, symbol, price, quantity, type, datetime) VALUES (?, ?, ?, ?, ?, 'sell', datetime('now'))",
                           session["user_id"], quote["name"], symbol, quote["price"], shares)
                db.execute("DELETE FROM holdings WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
