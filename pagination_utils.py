from flask import current_app, request


def paginate(query, per_page=None):
    """Paginate a SQLAlchemy query using the ?page= value in the address."""
    per_page = per_page or current_app.config["DEFAULT_PAGE_SIZE"]
    page = request.args.get("page", 1, type=int) or 1
    return query.paginate(page=max(page, 1), per_page=per_page, error_out=False)
