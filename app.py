import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

import requests
import json

from helpers import apology, login_required, lookup, usd

from datetime import datetime
# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")




@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def show_address(str):
    ip1 = request.remote_addr
    ip2= request.environ['REMOTE_ADDR']
    ip3 = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    print("\n\n\n" +str + "\n" + ip1)
    print(ip2)
    print(ip3 + "\n\n\n")
    request_url = 'https://geolocation-db.com/jsonp/' + ip3
    # Send request and decode the result
    response = requests.get(request_url)
    result = response.content.decode()
    # Clean the returned string so it just contains the dictionary data for the IP address
    result = result.split("(")[1].strip(")")
    # Convert this data into a dictionary
    result  = json.loads(result)
    print(result)
    return

@app.route("/")
@login_required
def index():
    show_address("index")
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    user_symbols = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id = ?", user_id)

    data = []
    total = 0
    for sym in user_symbols:
        shares_buy = db.execute("SELECT SUM(shares) FROM transactions WHERE type = ? AND symbol = ?", "BUY", sym["symbol"])
        shares_sell = db.execute("SELECT SUM(shares) FROM transactions WHERE type = ? AND symbol = ?", "SELL", sym["symbol"])

        shares = None
        if not shares_sell[0]["SUM(shares)"]:
            shares = shares_buy[0]["SUM(shares)"]
        else:
            shares = shares_buy[0]["SUM(shares)"] - shares_sell[0]["SUM(shares)"]

        market = lookup(sym["symbol"])
        symbol_price = market["price"]
        symbol_name = market["name"]

        total_price = shares * symbol_price

        total += total_price

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        data.append({'symbol': sym["symbol"], 'name': symbol_name, 'shares': shares,
                    'price': usd(symbol_price), 'total': usd(total_price)})

    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    return render_template("index.html", data=data, total=usd(total), cash=usd(cash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")

    symbol = request.form.get("symbol")
    if not symbol:
        return apology("Missing symbol", 400)

    result = lookup(symbol)
    if not result:
        return apology("Symbol not exist", 400)

    tmp_shares = request.form.get("shares")
    if tmp_shares.isnumeric() == False:
        return apology("Incorrect number of shares", 400)

    shares = int(tmp_shares)
    if not shares:
        return apology("Missing shares", 400)
    if shares < 1:
        return apology("Shares must be positive", 400)

    user_id = session["user_id"]

    current_price = result["price"]
    current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    total_price = current_price * shares
    if total_price > current_cash:
        return apology("Not enough cash", 400)

    my_time = datetime.now()
    db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash - total_price, user_id)
    db.execute("INSERT INTO transactions(user_id, type, symbol, price, shares, day, month, year, hour, minute, second) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
               user_id, "BUY", symbol, current_price, shares, my_time.day, my_time.month, my_time.year, my_time.hour, my_time.minute, my_time.second)

    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    data = db.execute("SELECT * FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", data=data)


@app.route("/login", methods=["GET", "POST"])
def login():
    show_address("login")
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

    symbol = request.form.get("symbol")
    if not symbol:
        return apology("Missing symbol", 400)
    result = lookup(symbol)

    if not result:
        return apology("Symbol not exist", 400)
    name = result["name"]
    price = usd(result["price"])
    sym = result["symbol"]

    return render_template("quoted.html", name=name, price=price, sym=sym)


@app.route("/register", methods=["GET", "POST"])
def register():
    show_address("register")
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        # check username
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 400)
        if db.execute("SELECT username FROM users WHERE username=?", username):
            return apology("user already exist", 400)

        # check password
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password:
            return apology("enter field for password", 400)
        if not confirmation:
            return apology("enter field for password confirmation", 400)
        if password != confirmation:
            return apology("password don't match", 400)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))
        return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    if request.method == "GET":
        user_symbols = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id = ?", user_id)

        for tmp in user_symbols:
            shares_buy = db.execute("SELECT SUM(shares) FROM transactions WHERE type = ? AND symbol = ?", "BUY", tmp["symbol"])
            shares_sell = db.execute("SELECT SUM(shares) FROM transactions WHERE type = ? AND symbol = ?", "SELL", tmp["symbol"])
            current_shares = None
            if not shares_sell[0]["SUM(shares)"]:
                current_shares = shares_buy[0]["SUM(shares)"]
            else:
                current_shares = shares_buy[0]["SUM(shares)"] - shares_sell[0]["SUM(shares)"]
            if current_shares == 0:
                tmp["symbol"] = "-"
        return render_template("sell.html", user_symbols=user_symbols)

    symbol_for_sell = request.form.get("symbol")
    shares_for_sell = request.form.get("shares")
    if not shares_for_sell:
        return apology("Missing shares", 400)

    shares_buy = db.execute("SELECT SUM(shares) FROM transactions WHERE type = ? AND symbol = ?", "BUY", symbol_for_sell)
    shares_sell = db.execute("SELECT SUM(shares) FROM transactions WHERE type = ? AND symbol = ?", "SELL", symbol_for_sell)
    current_shares = None
    if not shares_sell[0]["SUM(shares)"]:
        current_shares = shares_buy[0]["SUM(shares)"]
    else:
        current_shares = shares_buy[0]["SUM(shares)"] - shares_sell[0]["SUM(shares)"]

    if current_shares < int(shares_for_sell):
        return apology("Not enough shares", 400)
    new_shares = current_shares - int(shares_for_sell)
    print(new_shares)
    current_price = lookup(symbol_for_sell)["price"]
    current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    total_price = current_price * int(shares_for_sell)

    my_time = datetime.now()
    db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash + total_price, user_id)
    db.execute("INSERT INTO transactions(user_id, type, symbol, price, shares, day, month, year, hour, minute, second) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
               user_id, "SELL", symbol_for_sell, current_price, shares_for_sell, my_time.day, my_time.month, my_time.year, my_time.hour, my_time.minute, my_time.second)

    return redirect("/")


@app.route("/add_cash", methods=["GET", "POST"])
def add_cash():
    if request.method == "GET":
        return render_template("add_cash.html")
    add = int(request.form.get("cash"))
    if add < 0:
        return apology("Incorrect", 400)
    user_id = session["user_id"]
    current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash + add, user_id)
    return redirect("/")
