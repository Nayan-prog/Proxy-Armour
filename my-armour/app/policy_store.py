"""The live policy: config.yaml, overlaid with the `policies` table.

Kept in memory so /scan never waits on (or fails with) the database. Refreshed
at startup and after every PUT /api/policies; the proxy fetches it from
GET /internal/policies every policy_sync.poll_seconds.
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from armour_config import PolicySettings, settings
from app.detectors.engine import default_severities
from app.models import Policy, utcnow


class PolicyStore:
    def __init__(self, base: PolicySettings):
        self.base = base
        self.current = base

    def rows_to_settings(self, rows: list[Policy]) -> PolicySettings:
        # config.yaml types are the base, so a type added to a detector later
        # still has a policy even before someone saves it in the table
        return PolicySettings(
            default_action=self.base.default_action,
            types={**self.base.types, **{r.type: r.action for r in rows}},
            severities={**self.base.severities, **{r.type: r.severity for r in rows}},
        )

    def seed(self, session: Session) -> int:
        """Fill an EMPTY policies table from config.yaml. Returns rows inserted."""
        if session.scalar(select(Policy).limit(1)) is not None:
            return 0
        severities = default_severities()
        rows = [Policy(type=t, action=a, severity=severities.get(t, "high"),
                       updated_at=utcnow(), updated_by="config.yaml")
                for t, a in sorted(self.base.types.items())]
        session.add_all(rows)
        session.commit()
        return len(rows)

    def load(self, session: Session) -> PolicySettings:
        self.current = self.rows_to_settings(list(session.scalars(select(Policy))))
        return self.current

    def reset(self) -> None:
        self.current = self.base


STORE = PolicyStore(settings.policy)
