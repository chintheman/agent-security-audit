const express = require("express");
const { exec } = require("child_process");
const { requireAuth } = require("./auth");

const app = express();
app.use(requireAuth);

app.post("/run", (req, res) => {
  const cmd = req.body.cmd;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(3000);
