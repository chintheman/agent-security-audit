import subprocess

from flask import Flask, request
from auth import login_required

app = Flask(__name__)


@app.route("/run", methods=["POST"])
@login_required
def run_command():
    cmd = request.args.get("cmd")
    output = subprocess.run(cmd, shell=True, capture_output=True)
    return output.stdout
