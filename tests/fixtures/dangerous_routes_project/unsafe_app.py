import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run", methods=["POST"])
def run_command():
    cmd = request.args.get("cmd")
    output = subprocess.run(cmd, shell=True, capture_output=True)
    return output.stdout


@app.route("/status")
def status():
    return "ok"
