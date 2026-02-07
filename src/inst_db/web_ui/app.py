"""Flask web application for instruction database visualization."""
import os
from pathlib import Path
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    send_file,
)
from werkzeug.utils import secure_filename
import tempfile
import io

from . import config
from .utils.db_handler import DBSession
from .utils.dependency_graph import DependencyGraph


app = Flask(
    __name__,
    static_folder=str(config.STATIC_FOLDER),
    template_folder=str(config.TEMPLATE_FOLDER),
)
app.config.from_object(config)

# Store active database sessions
db_sessions = {}


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS


def get_db_session() -> DBSession:
    """Get or create database session for current client."""
    session_id = session.get("db_session_id")
    if session_id and session_id in db_sessions:
        return db_sessions[session_id]
    return None


@app.route("/")
def index():
    """Render main page."""
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
def upload_database():
    """Handle database file upload."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Please upload a .db, .sqlite, or .sqlite3 file"}), 400

    try:
        # Save uploaded file to temporary location
        filename = secure_filename(file.filename)
        temp_dir = tempfile.mkdtemp(dir=config.UPLOAD_FOLDER)
        db_path = os.path.join(temp_dir, filename)
        file.save(db_path)

        # Create database session
        db_session = DBSession(db_path)
        
        # Get statistics
        stats = db_session.get_statistics()
        
        # Store session
        session_id = os.path.basename(temp_dir)
        session["db_session_id"] = session_id
        db_sessions[session_id] = db_session

        return jsonify({
            "success": True,
            "filename": filename,
            "statistics": stats,
        })

    except Exception as e:
        return jsonify({"error": f"Failed to load database: {str(e)}"}), 500


@app.route("/api/instructions")
def get_instructions():
    """Get paginated instructions with optional filters."""
    db_session = get_db_session()
    if not db_session:
        return jsonify({"error": "No database loaded"}), 400

    try:
        page = int(request.args.get("page", 1))
        page_size = min(int(request.args.get("page_size", config.DEFAULT_PAGE_SIZE)), config.MAX_PAGE_SIZE)
        search = request.args.get("search", "").strip() or None
        register_filter = request.args.get("register", "").strip() or None
        order_by = request.args.get("order_by", "sequence_id")
        order_dir = request.args.get("order_dir", "asc")

        instructions, total = db_session.get_instructions(
            page=page,
            page_size=page_size,
            search=search,
            register_filter=register_filter,
            order_by=order_by,
            order_dir=order_dir,
        )

        return jsonify({
            "instructions": instructions,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/instruction/<int:sequence_id>")
def get_instruction_detail(sequence_id: int):
    """Get detailed information about a specific instruction."""
    db_session = get_db_session()
    if not db_session:
        return jsonify({"error": "No database loaded"}), 400

    try:
        detail = db_session.get_instruction_detail(sequence_id)
        if not detail:
            return jsonify({"error": "Instruction not found"}), 404

        return jsonify(detail)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/instruction/<int:sequence_id>/dependencies")
def get_dependencies(sequence_id: int):
    """Get dependency tree for an instruction."""
    db_session = get_db_session()
    if not db_session:
        return jsonify({"error": "No database loaded"}), 400

    try:
        max_depth = min(
            int(request.args.get("max_depth", config.DEFAULT_MAX_DEPTH)),
            config.MAX_DEPTH_LIMIT
        )
        format_type = request.args.get("format", "json")  # json or text

        conn = db_session.get_connection()
        dep_graph = DependencyGraph(conn)

        if format_type == "text":
            tree_text = dep_graph.build_tree_text(sequence_id, max_depth)
            return jsonify({
                "sequence_id": sequence_id,
                "format": "text",
                "tree": tree_text,
            })
        else:
            tree_json = dep_graph.build_tree_json(sequence_id, max_depth)
            return jsonify({
                "sequence_id": sequence_id,
                "format": "json",
                **tree_json,
            })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/registers")
def get_registers():
    """Get list of all registers in the database."""
    db_session = get_db_session()
    if not db_session:
        return jsonify({"error": "No database loaded"}), 400

    try:
        registers = db_session.get_all_registers()
        return jsonify({"registers": registers})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/statistics")
def get_statistics():
    """Get database statistics."""
    db_session = get_db_session()
    if not db_session:
        return jsonify({"error": "No database loaded"}), 400

    try:
        stats = db_session.get_statistics()
        return jsonify(stats)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export")
def export_data():
    """Export instructions to CSV or JSON."""
    db_session = get_db_session()
    if not db_session:
        return jsonify({"error": "No database loaded"}), 400

    try:
        format_type = request.args.get("format", "json")
        search = request.args.get("search", "").strip() or None
        register_filter = request.args.get("register", "").strip() or None

        filters = {
            "search": search,
            "register_filter": register_filter,
        }

        data = db_session.export_instructions(format=format_type, filters=filters)

        # Create response
        if format_type == "csv":
            output = io.BytesIO(data.encode("utf-8"))
            output.seek(0)
            return send_file(
                output,
                mimetype="text/csv",
                as_attachment=True,
                download_name="instructions.csv",
            )
        else:
            output = io.BytesIO(data.encode("utf-8"))
            output.seek(0)
            return send_file(
                output,
                mimetype="application/json",
                as_attachment=True,
                download_name="instructions.json",
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/close")
def close_database():
    """Close current database session."""
    session_id = session.get("db_session_id")
    if session_id and session_id in db_sessions:
        db_sessions[session_id].close()
        del db_sessions[session_id]
        session.pop("db_session_id", None)

    return jsonify({"success": True})


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Instruction Database Web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    print(f"Starting Instruction Database Web UI...")
    print(f"Open your browser and navigate to: http://{args.host}:{args.port}")
    
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
