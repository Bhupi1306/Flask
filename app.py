import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT * FROM purchase WHERE username = (SELECT username FROM users WHERE id = ?)", session["user_id"])
    cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    total = cash[0]["cash"]
    for stock in stocks:
        total += stock["total"]
    return render_template("index.html", stocks = stocks, total = usd(total), cash = usd(cash[0]["cash"]))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Symbol cannot be empty")

        stock = lookup(symbol)
        if not stock:
            return apology("Enter valid symbol")

        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except ValueError:
            return apology("Enter valid share")

        if not shares or shares<1:
            return apology("Enter valid number of shares")


        row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"],)

        if len(row) != 1:
            return apology("Could not find username")

        price = stock["price"] * shares

        if row[0]["cash"] < price:
            return apology("Not enough balance")

        check = db.execute("SELECT * FROM purchase WHERE symbol = ? AND username = (SELECT username FROM users WHERE id = ?)", stock["symbol"], session["user_id"])

        if len(check) == 0:
            try:
                db.execute("INSERT INTO purchase(username, symbol, shares, cost, total) VALUES(?,?,?,?,?);", row[0]["username"], stock["symbol"],shares,stock["price"],price)
            except:
                return apology("Some error occured While purchasing")

        else:
            try:
                db.execute("UPDATE purchase SET shares = ?, total = ? WHERE symbol = ?", check[0]["shares"] + shares, round((check[0]["shares"] + shares) * stock["price"],2), stock["symbol"])
            except:
                return apology("Error in updation")

        try:
            db.execute("UPDATE users SET cash = ? WHERE id = ?;", row[0]["cash"] - price, session["user_id"])
        except:
            return apology("Error while updating cash")

        try:
            db.execute("INSERT INTO transactions(id,symbol,shares,cost,total,status) VALUES(?,?,?,?,?,?)", session["user_id"], stock["symbol"], shares, stock["price"], round(shares * stock["price"],2), "BUY")
        except:
            return apology("Error while updating transaction")

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    try:
        transaction = db.execute("SELECT * FROM transactions WHERE id = ?", session["user_id"])
    except:
        return apology("Transaction not attained")

    return render_template("history.html", transaction = transaction)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stocks = lookup(symbol)
        if not stocks:
            return apology("No symbols found")
        return render_template("quoted.html", stocks = stocks)
    else:
        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():

    session.clear()
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return apology("must provide Username")

        password = request.form.get("password")
        if not password:
            return apology("must provide Password")

        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("Password not confirmed")

        if password != confirmation:
            return apology("Confirmation does not match the password")

        try:
            db.execute("INSERT INTO users(username,hash) VALUES (?,?)",username,generate_password_hash(password))
        except ValueError:
            return apology("Username already present")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stocks = db.execute("SELECT * FROM purchase WHERE username = (SELECT username FROM users WHERE id = ?)", session["user_id"])


    if request.method == "POST":
        stock = request.form.get("stock")
        if not stock:
            return apology("please select stock")

        owned_stocks = []
        stock_sell = {}

        for x in stocks:
            if stock == x["symbol"]:
                stock_sell = x

            owned_stocks.append(x["symbol"])

        if stock not in owned_stocks:
            return ("Please select valid stock")

        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except ValueError:
                return apology("Please enter a valid share")


        if not shares or shares < 1 or shares > stock_sell["shares"]:
            return apology("Please enter valid shares")

        total = round(stock_sell["cost"] * shares, 2)

        try:
             db.execute("INSERT INTO transactions(id,symbol,shares,cost,total,status) VALUES(?,?,?,?,?,?)", session["user_id"], stock_sell["symbol"], shares, stock_sell["cost"], total, "SELL")
        except:
            return apology("Error in transaction")

        earned = shares * stock_sell["cost"]

        if shares != stock_sell["shares"]:
            try:
                db.execute("UPDATE purchase SET shares = ?, total = ? WHERE username = (SELECT username FROM users WHERE id = ?) AND symbol = ?;", stock_sell["shares"] - shares, (stock_sell["shares"] - shares)*stock_sell["cost"], session["user_id"], stock_sell["symbol"])
            except:
                return apology("Purchase Not updated")
        else:
            try:
                db.execute("DELETE FROM purchase WHERE username = (SELECT username FROM users WHERE id = ?) AND symbol = ?", session["user_id"], stock_sell["symbol"])
            except:
                return apology("Purchase Not updated")

        try:
            user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            cash = user[0]["cash"]
            db.execute("UPDATE users SET cash = ? WHERE id = ? ", cash+ earned, session["user_id"])

        except:
            return apology("Cash not updated")




        return redirect("/")
    else:
        return render_template("sell.html", stocks = stocks)
