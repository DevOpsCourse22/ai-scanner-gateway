"""The gateway's database engine survives a database restart, and never
writes bound values - session ids, tokens - into error messages.

Both found on 2026-09-30 in the first deployment's acceptance tests:
deleting the Postgres Pod left the gateway's pooled connections pointing at
the old server process, the next request failed with a 500, and that 500's
traceback carried a live session id into the Pod log.
"""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from review_gateway import db


def _engine(tmp_path):
    return db._make_engine(f"sqlite:///{tmp_path / 'resilience.db'}")


def test_a_connection_that_died_while_pooled_is_replaced_not_served(tmp_path):
    """What a Postgres restart does: a connection dies while it sits idle in
    the pool, and SQLAlchemy does not know. Closing the idle DBAPI connection
    by hand is the SQLite equivalent. Without pool_pre_ping the next request
    gets the dead connection and fails."""
    engine = _engine(tmp_path)
    with engine.connect() as conn:
        conn.execute(text("select 1"))

    # Internal attribute, deliberately: reaching the idle connection is the
    # only way to kill it the way a server restart does.
    idle = engine.pool._pool.queue[0]
    idle.dbapi_connection.close()

    with engine.connect() as conn:
        assert conn.execute(text("select 1")).scalar() == 1


def test_bound_values_never_reach_an_error_message(tmp_path):
    """The gateway binds session ids and access tokens into its queries. A
    failing query must not carry them into the exception text, which is what
    ends up in logs."""
    engine = _engine(tmp_path)
    secret = "live-session-id-that-must-not-be-logged"

    with pytest.raises(DBAPIError) as failure:
        with engine.connect() as conn:
            conn.execute(text("select * from no_such_table where id = :id"),
                         {"id": secret})

    assert secret not in str(failure.value)


def test_the_engine_the_gateway_actually_uses_has_both_protections():
    """The tests above exercise _make_engine; this pins that the module-level
    engine really is built by it, so the protections cannot be bypassed by
    someone constructing the engine differently later."""
    assert db._engine.pool._pre_ping is True
    assert db._engine.hide_parameters is True
