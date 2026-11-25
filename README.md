# Jill's Budget

A tiny site for tracking spending against a monthly amount. No dependencies — just Node.

## Run it

```sh
PASSCODE=something ADMIN_PASSCODE=something-else npm start
```

Then open http://localhost:3000.

- **`PASSCODE`** — log in and add or remove spending.
- **`ADMIN_PASSCODE`** — the same, plus setting the monthly amount.

A new amount applies from the month you set it in onward; earlier months keep the amount they had.

## Hosting

Data lives in one file, `budget.json`, inside `DATA_DIR` (default `./data`). On a host, point
`DATA_DIR` at a persistent disk or volume so the data survives redeploys.

| Variable | Purpose |
| --- | --- |
| `PASSCODE` | Everyday passcode (required) |
| `ADMIN_PASSCODE` | Passcode that can also set the monthly amount (required) |
| `DATA_DIR` | Where `budget.json` is kept |
| `PORT` | Port to listen on (default 3000) |
