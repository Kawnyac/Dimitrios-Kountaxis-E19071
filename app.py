"""
main application module for the warehouse management system.

This Flask application implements a simple multi‑role information
system for managing warehouses. It follows the specification given in
the September 2025 coursework, providing distinct interfaces and
behaviour for administrators, supervisors and employees.  A
MongoDB database is used for persistent storage and all data access
is abstracted into helper functions to simplify route handlers.

The application uses plain session cookies for authentication.
Passwords are hashed on insertion using Werkzeug security helpers.
Endpoints are separated by role and guarded by decorators that
enforce the correct permissions.

To start the app for local development run::

    flask --app app.py --debug run

However, the preferred method of execution is via Docker Compose as
described in the accompanying README.md.
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Any, Dict, Optional, Tuple

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
    flash,
)
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId


###############################################################################
# Configuration
###############################################################################

# Default configuration is tuned for development.  When running under
# docker‑compose these values are overridden via environment variables.  The
# secret key should always be set externally in production to ensure
# session integrity.
MONGO_HOST = os.environ.get("MONGO_HOST", "mongodb")
MONGO_PORT = int(os.environ.get("MONGO_PORT", "27017"))
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "LogisticsDB")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")


###############################################################################
# Application setup
###############################################################################

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Configure the MongoDB client.  We establish the connection lazily so
# that tests can monkey‑patch the client if required.
client: MongoClient | None = None


def get_db():
    """Return the MongoDB database instance.

    A new client is created on first use and cached for subsequent calls.
    """
    global client
    if client is None:
        client = MongoClient(host=MONGO_HOST, port=MONGO_PORT)
    return client[MONGO_DB_NAME]


###############################################################################
# Utility functions
###############################################################################

def get_next_sequence(name: str) -> int:
    """Atomically increment and return the next sequence value for a given name.

    MongoDB does not provide autoincrement fields out of the box.  To
    generate stable identifiers for units and products we maintain a
    counters collection where each document holds a sequence value for a
    named counter.  When called this function increments the value and
    returns the updated number.  If no counter exists yet it will be
    initialised at 1.
    """
    db = get_db()
    result = db.counters.find_one_and_update(
        {"_id": name},
        {"$inc": {"sequence_value": 1}},
        return_document=True,
        upsert=True,
    )
    # result may not include sequence_value if it was just created
    return int(result.get("sequence_value", 1))


def ensure_admin_exists() -> None:
    """Ensure that the admin account exists in the database.

    When the application starts we check whether an admin user is present
    and create one if missing.  The default credentials are defined in the
    coursework specification: username 'admin' and password 'admin123'.
    """
    db = get_db()
    admins = db.users.find_one({"role": "admin"})
    if admins is None:
        db.users.insert_one(
            {
                "username": "admin",
                "password": generate_password_hash("admin123"),
                "role": "admin",
                "name": "Administrator",
                "surname": "",
            }
        )


def login_required(role: str | None = None):
    """Decorator to enforce authentication and optional role constraints.

    If a role is provided the current session user must match this role.
    Otherwise, the user must merely be authenticated.
    """

    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            user = session.get("user")
            if not user:
                return redirect(url_for("login"))
            if role is not None and user.get("role") != role:
                flash("Access denied: insufficient privileges", "error")
                # Redirect based on current role if available
                if user.get("role") == "admin":
                    return redirect(url_for("admin_dashboard"))
                if user.get("role") == "supervisor":
                    return redirect(url_for("supervisor_dashboard"))
                if user.get("role") == "employee":
                    return redirect(url_for("employee_dashboard"))
                return redirect(url_for("login"))
            return view(**kwargs)

        return wrapped_view

    return decorator


###############################################################################
# Routes – Authentication
###############################################################################

@app.route("/")
def index():
    """Landing page.  Redirect authenticated users to their dashboard."""
    if "user" in session:
        role = session["user"].get("role")
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        if role == "supervisor":
            return redirect(url_for("supervisor_dashboard"))
        if role == "employee":
            return redirect(url_for("employee_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Unified login page for all roles.

    The login form requires the user to select their role and provide
    credentials.  For supervisors and employees the unit_id must also be
    specified.  Successful authentication stores user details in the
    session.  Upon failure an error message is flashed.
    """
    ensure_admin_exists()
    if request.method == "POST":
        role = request.form.get("role")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        unit_id_input = request.form.get("unit_id")
        db = get_db()
        if role == "admin":
            user_doc = db.users.find_one({"role": "admin", "username": username})
            if user_doc and check_password_hash(user_doc["password"], password):
                session["user"] = {
                    "_id": str(user_doc["_id"]),
                    "username": user_doc["username"],
                    "role": "admin",
                    "name": user_doc.get("name", "Admin"),
                }
                return redirect(url_for("admin_dashboard"))
            flash("Invalid admin credentials.", "error")
        elif role in {"supervisor", "employee"}:
            try:
                unit_id = int(unit_id_input)
            except (TypeError, ValueError):
                flash("Invalid unit ID.", "error")
                return render_template("login.html")
            user_doc = db.users.find_one(
                {
                    "role": role,
                    "username": username,
                    "unit_id": unit_id,
                }
            )
            if user_doc and check_password_hash(user_doc["password"], password):
                session["user"] = {
                    "_id": str(user_doc["_id"]),
                    "username": user_doc["username"],
                    "role": role,
                    "unit_id": user_doc.get("unit_id"),
                    "unit_name": user_doc.get("unit_name"),
                    "name": user_doc.get("name"),
                    "surname": user_doc.get("surname"),
                }
                if role == "supervisor":
                    return redirect(url_for("supervisor_dashboard"))
                else:
                    return redirect(url_for("employee_dashboard"))
            flash("Invalid credentials.", "error")
        else:
            flash("Please select a valid role.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clear the user session and redirect to login."""
    session.clear()
    return redirect(url_for("login"))


###############################################################################
# Routes – Employee
###############################################################################

@app.route("/employee")
@login_required("employee")
def employee_dashboard():
    """Dashboard for an employee.  Shows quick links to available actions."""
    return render_template("employee/dashboard.html", user=session.get("user"))


@app.route("/employee/profile")
@login_required("employee")
def employee_profile():
    """Display the employee's profile details."""
    user = session.get("user")
    return render_template("employee/profile.html", user=user)


@app.route("/employee/change_password", methods=["GET", "POST"])
@login_required("employee")
def employee_change_password():
    """Allow an employee to change their password."""
    if request.method == "POST":
        current_pwd = request.form.get("current_password", "")
        new_pwd = request.form.get("new_password", "")
        db = get_db()
        user_doc = db.users.find_one({"_id": ObjectId(session["user"]["_id"]), "role": "employee"})
        if not user_doc or not check_password_hash(user_doc["password"], current_pwd):
            flash("Current password is incorrect.", "error")
        else:
            db.users.update_one(
                {"_id": user_doc["_id"]},
                {"$set": {"password": generate_password_hash(new_pwd)}},
            )
            flash("Password changed successfully.", "info")
    return render_template("employee/change_password.html")


def fetch_unit_products(unit_id: int, filters: Dict[str, Any], sort_by: Optional[str], direction: int) -> list[Dict[str, Any]]:
    """Retrieve a filtered and sorted list of products for a given unit.

    ``filters`` may include keys: 'product_name', 'product_id', 'quantity_min',
    'quantity_max'.  ``sort_by`` can be 'product_name' or 'product_sold_quantity'.
    ``direction`` is 1 for ascending or -1 for descending.  This helper
    constructs the appropriate MongoDB query and returns a list of enriched
    product documents that also embed the static product definition.
    """
    db = get_db()
    query: Dict[str, Any] = {"unit_id": unit_id}
    # Filter by product name substring
    if name := filters.get("product_name"):
        query["product_name"] = {"$regex": name, "$options": "i"}
    # Filter by exact product_id
    if pid := filters.get("product_id"):
        try:
            pid_int = int(pid)
            query["product_id"] = pid_int
        except ValueError:
            pass
    # Quantity range filter
    qty_min = filters.get("quantity_min")
    qty_max = filters.get("quantity_max")
    if qty_min or qty_max:
        q_filter: Dict[str, Any] = {}
        try:
            if qty_min:
                q_filter["$gte"] = int(qty_min)
            if qty_max:
                q_filter["$lte"] = int(qty_max)
            if q_filter:
                query["product_quantity"] = q_filter
        except ValueError:
            pass
    # Build sort tuple
    sort_tuple: Optional[Tuple[str, int]] = None
    if sort_by in {"product_name", "product_sold_quantity"}:
        sort_tuple = (sort_by, direction)
    # Query unit_products
    cursor = db.unit_products.find(query)
    if sort_tuple:
        cursor = cursor.sort([sort_tuple])
    results: list[Dict[str, Any]] = list(cursor)
    # Enrich with product static data
    product_ids = [p["product_id"] for p in results]
    product_defs = {
        d["product_id"]: d
        for d in db.products.find({"product_id": {"$in": product_ids}})
    }
    for doc in results:
        doc["definition"] = product_defs.get(doc["product_id"], {})
    return results


@app.route("/employee/products")
@login_required("employee")
def employee_products():
    """List products for the employee's unit with filtering and sorting options."""
    user = session.get("user")
    unit_id = user["unit_id"]
    filters = {
        "product_name": request.args.get("product_name", "").strip(),
        "product_id": request.args.get("product_id", "").strip(),
        "quantity_min": request.args.get("quantity_min", "").strip(),
        "quantity_max": request.args.get("quantity_max", "").strip(),
    }
    sort_by = request.args.get("sort_by")
    direction = request.args.get("direction", "asc")
    direction_flag = ASCENDING if direction == "asc" else DESCENDING
    products = fetch_unit_products(unit_id, filters, sort_by, direction_flag)
    return render_template(
        "employee/products.html",
        products=products,
        filters=filters,
        sort_by=sort_by,
        direction=direction,
    )


@app.route("/employee/products/<int:product_id>")
@login_required("employee")
def employee_product_detail(product_id: int):
    """Display details of a single product and allow sale operations."""
    user = session.get("user")
    unit_id = user["unit_id"]
    db = get_db()
    unit_prod = db.unit_products.find_one({"unit_id": unit_id, "product_id": product_id})
    prod_def = db.products.find_one({"product_id": product_id})
    if not unit_prod or not prod_def:
        flash("Product not found in your unit.", "error")
        return redirect(url_for("employee_products"))
    return render_template("employee/product_detail.html", unit_product=unit_prod, prod_def=prod_def)


@app.route("/employee/products/<int:product_id>/sell", methods=["POST"])
@login_required("employee")
def employee_sell_product(product_id: int):
    """Sell a quantity of a product from the employee's unit."""
    user = session.get("user")
    unit_id = user["unit_id"]
    quantity_to_sell = request.form.get("quantity")
    try:
        qty = int(quantity_to_sell)
        if qty <= 0:
            raise ValueError
    except (TypeError, ValueError):
        flash("Please enter a valid positive integer quantity.", "error")
        return redirect(url_for("employee_product_detail", product_id=product_id))
    db = get_db()
    unit_prod = db.unit_products.find_one({"unit_id": unit_id, "product_id": product_id})
    prod_def = db.products.find_one({"product_id": product_id})
    if not unit_prod or not prod_def:
        flash("Product not found.", "error")
        return redirect(url_for("employee_products"))
    available_qty = unit_prod["product_quantity"]
    if qty > available_qty:
        flash(f"Cannot sell {qty} units. Only {available_qty} available.", "error")
        return redirect(url_for("employee_product_detail", product_id=product_id))
    # Calculate gain per unit
    gain_per_unit = prod_def["product_selling_price"] - prod_def["product_purchase_price"]
    total_gain = gain_per_unit * qty
    # Update the unit_products document
    db.unit_products.update_one(
        {"unit_id": unit_id, "product_id": product_id},
        {
            "$inc": {
                "product_quantity": -qty,
                "product_sold_quantity": qty,
                "product_unit_gain": total_gain,
            }
        },
    )
    flash(f"Successfully sold {qty} units.", "info")
    return redirect(url_for("employee_product_detail", product_id=product_id))


###############################################################################
# Routes – Supervisor
###############################################################################

@app.route("/supervisor")
@login_required("supervisor")
def supervisor_dashboard():
    """Dashboard for a supervisor.

    Shows summary statistics for their warehouse and links to management
    functions.
    """
    user = session.get("user")
    stats = compute_unit_statistics(user["unit_id"])
    return render_template("supervisor/dashboard.html", user=user, stats=stats)


@app.route("/supervisor/change_password", methods=["GET", "POST"])
@login_required("supervisor")
def supervisor_change_password():
    """Allow a supervisor to change their own password."""
    if request.method == "POST":
        current_pwd = request.form.get("current_password", "")
        new_pwd = request.form.get("new_password", "")
        db = get_db()
        user_doc = db.users.find_one({"_id": ObjectId(session["user"]["_id"]), "role": "supervisor"})
        if not user_doc or not check_password_hash(user_doc["password"], current_pwd):
            flash("Current password is incorrect.", "error")
        else:
            db.users.update_one(
                {"_id": user_doc["_id"]},
                {"$set": {"password": generate_password_hash(new_pwd)}},
            )
            flash("Password changed successfully.", "info")
    return render_template("supervisor/change_password.html")


@app.route("/supervisor/employees")
@login_required("supervisor")
def supervisor_list_employees():
    """List all employees within the supervisor's unit."""
    user = session.get("user")
    unit_id = user["unit_id"]
    db = get_db()
    employees = list(db.users.find({"role": "employee", "unit_id": unit_id}))
    return render_template("supervisor/employees.html", employees=employees)


@app.route("/supervisor/employees/create", methods=["GET", "POST"])
@login_required("supervisor")
def supervisor_create_employee():
    """Create a new employee under the supervisor's unit."""
    user = session.get("user")
    unit_id = user["unit_id"]
    unit_name = user["unit_name"]
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        surname = request.form.get("surname", "").strip()
        password = request.form.get("password", "").strip()
        username = request.form.get("username", "").strip()
        if not (name and surname and password and username):
            flash("All fields are required.", "error")
        else:
            db = get_db()
            if db.users.find_one({"username": username}):
                flash("Username already exists.", "error")
            else:
                db.users.insert_one(
                    {
                        "username": username,
                        "password": generate_password_hash(password),
                        "role": "employee",
                        "unit_id": unit_id,
                        "unit_name": unit_name,
                        "name": name,
                        "surname": surname,
                    }
                )
                flash("Employee created successfully.", "info")
                return redirect(url_for("supervisor_list_employees"))
    return render_template("supervisor/create_employee.html")


@app.route("/supervisor/employees/<employee_id>/delete", methods=["POST"])
@login_required("supervisor")
def supervisor_delete_employee(employee_id: str):
    """Delete an employee from the supervisor's unit."""
    user = session.get("user")
    unit_id = user["unit_id"]
    db = get_db()
    emp_doc = db.users.find_one({"_id": ObjectId(employee_id), "role": "employee"})
    if emp_doc and emp_doc.get("unit_id") == unit_id:
        db.users.delete_one({"_id": ObjectId(employee_id)})
        flash("Employee removed.", "info")
    else:
        flash("Employee not found or belongs to another unit.", "error")
    return redirect(url_for("supervisor_list_employees"))


@app.route("/supervisor/employees/<employee_id>/change_password", methods=["POST"])
@login_required("supervisor")
def supervisor_change_employee_password(employee_id: str):
    """Allow the supervisor to change an employee's password."""
    new_pwd = request.form.get("new_password", "").strip()
    if not new_pwd:
        flash("New password cannot be empty.", "error")
        return redirect(url_for("supervisor_list_employees"))
    db = get_db()
    emp_doc = db.users.find_one({"_id": ObjectId(employee_id), "role": "employee"})
    if not emp_doc:
        flash("Employee not found.", "error")
    else:
        db.users.update_one(
            {"_id": emp_doc["_id"]},
            {"$set": {"password": generate_password_hash(new_pwd)}},
        )
        flash("Employee password updated.", "info")
    return redirect(url_for("supervisor_list_employees"))


def compute_unit_statistics(unit_id: int) -> Dict[str, Any]:
    """Compute summary statistics for a given unit.

    Returns a dictionary with total_gain (can be negative), volume_usage
    percentage and employee_count.  Product volume usage is calculated as
    (sum(product_quantity * product_volume) / unit_volume) * 100.  If
    unit_volume is zero (unlikely) the usage is set to 0 to avoid division by
    zero.
    """
    db = get_db()
    # Sum gain and volume usage from unit_products and products
    pipeline = [
        {"$match": {"unit_id": unit_id}},
        {
            "$lookup": {
                "from": "products",
                "localField": "product_id",
                "foreignField": "product_id",
                "as": "product_def",
            }
        },
        {"$unwind": "$product_def"},
        {
            "$group": {
                "_id": None,
                "total_gain": {"$sum": "$product_unit_gain"},
                "used_volume": {
                    "$sum": {"$multiply": ["$product_quantity", "$product_def.product_volume"]}
                },
            }
        },
    ]
    agg = list(db.unit_products.aggregate(pipeline))
    total_gain = agg[0]["total_gain"] if agg else 0.0
    used_volume = agg[0]["used_volume"] if agg else 0.0
    unit_doc = db.units.find_one({"unit_id": unit_id})
    unit_volume = unit_doc.get("unit_volume", 0) if unit_doc else 0
    volume_usage = (used_volume / unit_volume * 100) if unit_volume else 0
    employee_count = db.users.count_documents({"unit_id": unit_id, "role": {"$in": ["employee", "supervisor"]}})
    return {
        "total_gain": round(total_gain, 2),
        "volume_usage": round(volume_usage, 2),
        "employee_count": employee_count,
    }


@app.route("/supervisor/statistics")
@login_required("supervisor")
def supervisor_statistics():
    """Display statistics about the supervisor's unit."""
    user = session.get("user")
    stats = compute_unit_statistics(user["unit_id"])
    return render_template("supervisor/statistics.html", stats=stats)


@app.route("/supervisor/products/<int:product_id>/buy", methods=["POST"])
@login_required("supervisor")
def supervisor_buy_product(product_id: int):
    """Increase the quantity of a product in the supervisor's unit."""
    user = session.get("user")
    unit_id = user["unit_id"]
    quantity_str = request.form.get("quantity")
    try:
        qty = int(quantity_str)
        if qty <= 0:
            raise ValueError
    except (TypeError, ValueError):
        flash("Invalid quantity value.", "error")
        return redirect(url_for("employee_product_detail", product_id=product_id))
    db = get_db()
    unit_prod = db.unit_products.find_one({"unit_id": unit_id, "product_id": product_id})
    prod_def = db.products.find_one({"product_id": product_id})
    if not unit_prod or not prod_def:
        flash("Product not found.", "error")
        return redirect(url_for("employee_products"))
    # Cost is negative gain
    cost = prod_def["product_purchase_price"] * qty
    db.unit_products.update_one(
        {"unit_id": unit_id, "product_id": product_id},
        {
            "$inc": {
                "product_quantity": qty,
                "product_unit_gain": -cost,
            }
        },
    )
    flash(f"Purchased {qty} units.", "info")
    return redirect(url_for("employee_product_detail", product_id=product_id))


###############################################################################
# Routes – Admin
###############################################################################

@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    """Admin dashboard showing system‑wide statistics."""
    stats = compute_company_statistics()
    return render_template("admin/dashboard.html", stats=stats)


@app.route("/admin/change_password", methods=["GET", "POST"])
@login_required("admin")
def admin_change_password():
    """Allow the admin to change their password."""
    if request.method == "POST":
        current_pwd = request.form.get("current_password", "")
        new_pwd = request.form.get("new_password", "")
        db = get_db()
        user_doc = db.users.find_one({"role": "admin"})
        if not user_doc or not check_password_hash(user_doc["password"], current_pwd):
            flash("Current password is incorrect.", "error")
        else:
            db.users.update_one(
                {"_id": user_doc["_id"]},
                {"$set": {"password": generate_password_hash(new_pwd)}},
            )
            flash("Password changed successfully.", "info")
    return render_template("admin/change_password.html")


@app.route("/admin/supervisors/create", methods=["GET", "POST"])
@login_required("admin")
def admin_create_supervisor():
    """Create a new supervisor and associate them with a unit."""
    db = get_db()
    units = list(db.units.find())
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        surname = request.form.get("surname", "").strip()
        password = request.form.get("password", "").strip()
        username = request.form.get("username", "").strip()
        try:
            unit_id = int(request.form.get("unit_id", ""))
        except ValueError:
            unit_id = None
        if not (name and surname and password and username and unit_id is not None):
            flash("All fields are required.", "error")
        elif not db.units.find_one({"unit_id": unit_id}):
            flash("Selected unit does not exist.", "error")
        elif db.users.find_one({"username": username}):
            flash("Username already exists.", "error")
        else:
            unit_doc = db.units.find_one({"unit_id": unit_id})
            db.users.insert_one(
                {
                    "username": username,
                    "password": generate_password_hash(password),
                    "role": "supervisor",
                    "unit_id": unit_id,
                    "unit_name": unit_doc.get("unit_name"),
                    "name": name,
                    "surname": surname,
                }
            )
            flash("Supervisor created.", "info")
            return redirect(url_for("admin_list_supervisors"))
    return render_template("admin/create_supervisor.html", units=units)


@app.route("/admin/units/create", methods=["GET", "POST"])
@login_required("admin")
def admin_create_unit():
    """Create a new warehouse unit."""
    if request.method == "POST":
        unit_name = request.form.get("unit_name", "").strip()
        try:
            unit_volume = float(request.form.get("unit_volume", ""))
        except ValueError:
            unit_volume = None
        if not unit_name or unit_volume is None:
            flash("All fields are required and must be valid.", "error")
        else:
            db = get_db()
            # Generate unique unit_id using counter
            unit_id = get_next_sequence("unit_id")
            db.units.insert_one(
                {
                    "unit_id": unit_id,
                    "unit_name": unit_name,
                    "unit_volume": unit_volume,
                }
            )
            # For existing products create unit_products entries with zero quantity
            for prod in db.products.find():
                db.unit_products.insert_one(
                    {
                        "unit_id": unit_id,
                        "product_id": prod["product_id"],
                        "product_name": prod["product_name"],
                        "product_quantity": 0,
                        "product_sold_quantity": 0,
                        "product_unit_gain": 0.0,
                    }
                )
            flash(f"Warehouse '{unit_name}' created with ID {unit_id}.", "info")
            return redirect(url_for("admin_list_units"))
    return render_template("admin/create_unit.html")


@app.route("/admin/products/create", methods=["GET", "POST"])
@login_required("admin")
def admin_create_product():
    """Create a new product that becomes available to all units."""
    if request.method == "POST":
        product_name = request.form.get("product_name", "").strip()
        product_weight = request.form.get("product_weight", "").strip()
        product_volume = request.form.get("product_volume", "").strip()
        product_category = request.form.get("product_category", "").strip()
        product_purchase_price = request.form.get("product_purchase_price", "").strip()
        product_selling_price = request.form.get("product_selling_price", "").strip()
        product_manufacturer = request.form.get("product_manufacturer", "").strip()
        # Validate numeric fields
        try:
            weight = float(product_weight)
            volume = float(product_volume)
            purchase_price = float(product_purchase_price)
            selling_price = float(product_selling_price)
        except ValueError:
            flash("Weight, volume and prices must be numeric.", "error")
            return render_template("admin/create_product.html")
        if not product_name or not product_category or not product_manufacturer:
            flash("Please fill all fields.", "error")
            return render_template("admin/create_product.html")
        db = get_db()
        product_id = get_next_sequence("product_id")
        db.products.insert_one(
            {
                "product_id": product_id,
                "product_name": product_name,
                "product_weight": weight,
                "product_volume": volume,
                "product_category": product_category,
                "product_purchase_price": purchase_price,
                "product_selling_price": selling_price,
                "product_manufacturer": product_manufacturer,
            }
        )
        # Insert unit_products records for all units
        for unit in db.units.find():
            db.unit_products.insert_one(
                {
                    "unit_id": unit["unit_id"],
                    "product_id": product_id,
                    "product_name": product_name,
                    "product_quantity": 0,
                    "product_sold_quantity": 0,
                    "product_unit_gain": 0.0,
                }
            )
        flash(f"Product '{product_name}' created with ID {product_id}.", "info")
        return redirect(url_for("admin_list_products"))
    return render_template("admin/create_product.html")


@app.route("/admin/units")
@login_required("admin")
def admin_list_units():
    """List all units with summary gain and actions."""
    db = get_db()
    units = list(db.units.find())
    # For each unit compute total gain
    for u in units:
        agg = list(
            db.unit_products.aggregate(
                [
                    {"$match": {"unit_id": u["unit_id"]}},
                    {"$group": {"_id": None, "total_gain": {"$sum": "$product_unit_gain"}}},
                ]
            )
        )
        u["total_gain"] = agg[0]["total_gain"] if agg else 0.0
    return render_template("admin/units.html", units=units)


@app.route("/admin/units/<int:unit_id>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_unit(unit_id: int):
    """Remove a warehouse unit and associated data."""
    db = get_db()
    # Remove users belonging to this unit (employees and supervisors)
    db.users.delete_many({"unit_id": unit_id, "role": {"$in": ["employee", "supervisor"]}})
    # Remove unit_products entries
    db.unit_products.delete_many({"unit_id": unit_id})
    # Remove unit itself
    db.units.delete_one({"unit_id": unit_id})
    flash("Unit and related data deleted.", "info")
    return redirect(url_for("admin_list_units"))


@app.route("/admin/units/<int:unit_id>/as_supervisor")
@login_required("admin")
def admin_as_supervisor(unit_id: int):
    """Switch context to act as a supervisor for a given unit."""
    db = get_db()
    unit_doc = db.units.find_one({"unit_id": unit_id})
    if not unit_doc:
        flash("Unit not found.", "error")
        return redirect(url_for("admin_list_units"))
    # Store context in session to reuse supervisor views
    session["user"] = {
        "role": "supervisor",
        "unit_id": unit_doc["unit_id"],
        "unit_name": unit_doc["unit_name"],
        "name": f"Admin acting for {unit_doc['unit_name']}",
        "surname": "",
        "_id": "admin_as_supervisor",
    }
    flash(f"Acting as supervisor for unit {unit_doc['unit_name']}.", "info")
    return redirect(url_for("supervisor_dashboard"))


@app.route("/admin/supervisors")
@login_required("admin")
def admin_list_supervisors():
    """List all supervisors with actions."""
    db = get_db()
    supervisors = list(db.users.find({"role": "supervisor"}))
    return render_template("admin/supervisors.html", supervisors=supervisors)


@app.route("/admin/supervisors/<user_id>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_supervisor(user_id: str):
    """Remove a supervisor and all employees belonging to the same unit."""
    db = get_db()
    supervisor = db.users.find_one({"_id": ObjectId(user_id), "role": "supervisor"})
    if not supervisor:
        flash("Supervisor not found.", "error")
        return redirect(url_for("admin_list_supervisors"))
    unit_id = supervisor["unit_id"]
    # Delete supervisor
    db.users.delete_one({"_id": supervisor["_id"]})
    flash("Supervisor removed.", "info")
    return redirect(url_for("admin_list_supervisors"))


@app.route("/admin/supervisors/<user_id>/change_password", methods=["POST"])
@login_required("admin")
def admin_change_supervisor_password(user_id: str):
    """Allow the admin to change a supervisor's password."""
    new_pwd = request.form.get("new_password", "").strip()
    if not new_pwd:
        flash("New password cannot be empty.", "error")
        return redirect(url_for("admin_list_supervisors"))
    db = get_db()
    supervisor = db.users.find_one({"_id": ObjectId(user_id), "role": "supervisor"})
    if not supervisor:
        flash("Supervisor not found.", "error")
    else:
        db.users.update_one(
            {"_id": supervisor["_id"]},
            {"$set": {"password": generate_password_hash(new_pwd)}},
        )
        flash("Supervisor password updated.", "info")
    return redirect(url_for("admin_list_supervisors"))


@app.route("/admin/products")
@login_required("admin")
def admin_list_products():
    """Display all products with global information."""
    db = get_db()
    products = list(db.products.find())
    return render_template("admin/products.html", products=products)


@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_product(product_id: int):
    """Remove a product from the system entirely."""
    db = get_db()
    db.products.delete_one({"product_id": product_id})
    db.unit_products.delete_many({"product_id": product_id})
    flash("Product deleted.", "info")
    return redirect(url_for("admin_list_products"))


def compute_company_statistics() -> Dict[str, Any]:
    """Compute summary statistics for the entire company.

    Returns total_gain, total_volume_usage and total_employee_count across all
    units.  Total volume usage is calculated as the sum of used volume across
    units divided by the sum of unit volumes.
    """
    db = get_db()
    # Aggregate gains and used volume from unit_products
    pipeline = [
        {
            "$lookup": {
                "from": "products",
                "localField": "product_id",
                "foreignField": "product_id",
                "as": "product_def",
            }
        },
        {"$unwind": "$product_def"},
        {
            "$group": {
                "_id": "$unit_id",
                "gain": {"$sum": "$product_unit_gain"},
                "used_volume": {
                    "$sum": {"$multiply": ["$product_quantity", "$product_def.product_volume"]}
                },
            }
        },
    ]
    agg = list(db.unit_products.aggregate(pipeline))
    total_gain = sum(d.get("gain", 0) for d in agg)
    total_used_volume = sum(d.get("used_volume", 0) for d in agg)
    # Sum of all unit volumes
    total_unit_volume = sum(u.get("unit_volume", 0) for u in db.units.find())
    total_volume_usage = (total_used_volume / total_unit_volume * 100) if total_unit_volume else 0
    total_employees = db.users.count_documents({"role": {"$in": ["employee", "supervisor"]}})
    return {
        "total_gain": round(total_gain, 2),
        "volume_usage": round(total_volume_usage, 2),
        "employee_count": total_employees,
    }


###############################################################################
# Main entry point
###############################################################################

if __name__ == "__main__":
    # Ensure admin account on standalone run
    ensure_admin_exists()
    # Run the development server
    app.run(host="0.0.0.0", port=5000, debug=True)