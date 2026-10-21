"""Generate fake customer data for the lab (100% synthetic, no real people).

Usage (from the repo root):
    python scripts/gen_fake_data.py
Output:
    data/clients.csv   (git-ignored)
"""
import csv
import random
from pathlib import Path

from faker import Faker

ROWS = 50
SEED = 2026  # fixed seed: same file every run, so Terraform doesn't re-upload for nothing
CITIES = ["Rabat", "Sale", "Casablanca", "Kenitra", "Fes", "Meknes",
          "Tanger", "Marrakech", "Agadir", "Oujda", "Sidi Kacem"]

fake = Faker("fr_FR")
Faker.seed(SEED)
random.seed(SEED)

out = Path(__file__).resolve().parent.parent / "data" / "clients.csv"
out.parent.mkdir(exist_ok=True)

with out.open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["client_id", "full_name", "email", "phone", "city",
                "iban", "monthly_spend_mad", "created_at", "note"])
    for i in range(1, ROWS + 1):
        w.writerow([
            f"CL-{i:04d}",
            fake.name(),
            fake.email(),
            f"+2126{random.randint(10000000, 99999999)}",
            random.choice(CITIES),
            fake.iban(),
            random.randint(200, 20000),
            fake.date_between(start_date="-3y", end_date="today").isoformat(),
            "FAKE DATA - security lab",
        ])

print(f"Wrote {ROWS} fake rows to {out}")
