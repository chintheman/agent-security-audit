const express = require("express");
const { exec } = require("child_process");

const app = express();

app.post("/run", (req, res) => {
  const cmd = req.body.cmd;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(3000);
