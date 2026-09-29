# dangerous_routes_project fixture

For `network.unauthenticated_dangerous_route` (tests/checkers/test_network.py).

- `unsafe_app.py` -- Flask route with no auth, runs `subprocess.run(cmd,
  shell=True)` on `request.args.get("cmd")`. Must trigger.
- `safe_app.py` -- same shape, but decorated `@login_required`. Must stay
  silent.
- `server.js` -- Express route with no auth, runs `exec(cmd)` from
  `req.body.cmd`. Must trigger.
- `protected_server.js` -- same shape, but `app.use(requireAuth)` is
  registered before the route. Must stay silent.
