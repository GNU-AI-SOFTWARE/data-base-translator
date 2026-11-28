/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 Claire Ivanenka <claire@gnu-ai.org> */

/*
 * storage_pg.c — The libpq backend of /db.
 *
 * Design rules implemented here (PLAN.md sections 3 and 4):
 *
 *   - ONE connection, prepared ONCE per connection: the statement
 *     set is fixed by the frozen contract, never built by
 *     concatenation — every caller byte is a bound parameter.
 *   - The schema is applied idempotently at connect (the embedded
 *     copy of schema.sql), never destructively: CREATE TABLE IF
 *     NOT EXISTS, no DROP, no ALTER.
 *   - Expected constraints are statuses, not POSIX errors: a
 *     unique violation of checksum becomes DBT_ST_DUPLICATE with
 *     the existing id, a foreign key violation becomes
 *     DBT_ST_INVALID.  Only the transport layer (unreachable
 *     server, lost connection) fails, and the next attempt
 *     reconnects: the translator never dies on the database.
 *   - Zero allocation in the write path: the parameters are
 *     rendered into stack buffers bounded by the contract.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "storage_pg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpq-fe.h>

/* ---------------------------------------------------------------------
 *  State: the single connection of the MVP (PLAN.md section 4).
 * ------------------------------------------------------------------- */

static struct
  {
    PGconn *conn;
    bool    prepared;          /* statements ready on this connection */
    bool    schema_ok;        /* DDL applied on this connection */
    char    conninfo[512];
  } pg =
  {
    .conninfo = "dbname=gnuai",
  };

/* Statement names of the frozen set (see prepare_statements). */
#define STMT_INS_RUNS       "dbt_ins_runs"
#define STMT_INS_INSTANCES  "dbt_ins_run_instances"
#define STMT_INS_TRAINING   "dbt_ins_training_data"
#define STMT_INS_INCIDENTS  "dbt_ins_incidents"
#define STMT_INS_INGEST     "dbt_ins_ingest_jobs"
#define STMT_INS_AGG        "dbt_ins_aggregator_state"
#define STMT_SEL_CHECKSUM   "dbt_sel_checksum"

/* PostgreSQL type OIDs, so the server never has to infer: the
 * contract decides the types, not the values of the day. */
#define OID_JSONB 3802
#define OID_TEXT  25
#define OID_INT8  20
#define OID_INT4  23
#define OID_FLOAT4 700

/* ---------------------------------------------------------------------
 *  Diagnostics: the last transport message, kept for the status.
 * ------------------------------------------------------------------- */

static void
note_error (const char *msg)
{
  dbt_storage_set_error (msg);
}

static void
note_pg_error (void)
{
  note_error (pg.conn != NULL ? PQerrorMessage (pg.conn)
                              : "PostgreSQL unreachable");
}

/* ---------------------------------------------------------------------
 *  Connection: connect, apply the schema, prepare the statements.
 *  Returns true when the backend is ready to serve a write.
 * ------------------------------------------------------------------- */

static bool
prepare_statements (void)
{
  static const Oid ins_runs_types[3] = { OID_JSONB, OID_TEXT, OID_JSONB };
  static const Oid ins_ins_types[7] =
    { OID_INT8, OID_TEXT, OID_INT8, OID_JSONB, OID_JSONB, OID_FLOAT4,
      OID_TEXT };
  static const Oid ins_tr_types[4] =
    { OID_TEXT, OID_INT4, OID_TEXT, OID_TEXT };
  static const Oid sel_types[1] = { OID_TEXT };

  static const char ins_runs_sql[] =
    "INSERT INTO runs (descriptor, aggregate_strategy, final_output)"
    " VALUES ($1, $2, $3) RETURNING id";
  static const char ins_ins_sql[] =
    "INSERT INTO run_instances (run_id, topology, seed, input, output,"
    " score, status) VALUES ($1, $2, $3, $4, $5, $6, $7)"
    " RETURNING id";
  static const char ins_tr_sql[] =
    "INSERT INTO training_data (source_url, http_status, content,"
    " checksum) VALUES ($1, $2, $3, $4) RETURNING id";
  static const Oid ins_inc_types[3] =
    { OID_INT8, OID_INT8, OID_TEXT };
  static const char ins_inc_sql[] =
    "INSERT INTO incidents (run_id, instance_id, kind)"
    " VALUES ($1, $2, $3) RETURNING id";
  static const Oid ins_ing_types[3] = { OID_TEXT, OID_TEXT, OID_INT4 };
  static const char ins_ing_sql[] =
    "INSERT INTO ingest_jobs (source_url, status, records_added)"
    " VALUES ($1, $2, $3) RETURNING id";
  static const Oid ins_agg_types[3] = { OID_TEXT, OID_FLOAT4, OID_INT4 };
  static const char ins_agg_sql[] =
    "INSERT INTO aggregator_state (topology, weight, version)"
    " VALUES ($1, $2, $3) RETURNING id";
  static const char sel_sql[] =
    "SELECT id FROM training_data WHERE checksum = $1";

  PGresult *res[7];
  bool ok = true;

  res[0] = PQprepare (pg.conn, STMT_INS_RUNS, ins_runs_sql, 3,
                      ins_runs_types);
  res[1] = PQprepare (pg.conn, STMT_INS_INSTANCES, ins_ins_sql, 7,
                      ins_ins_types);
  res[2] = PQprepare (pg.conn, STMT_INS_TRAINING, ins_tr_sql, 4,
                      ins_tr_types);
  res[3] = PQprepare (pg.conn, STMT_INS_INCIDENTS, ins_inc_sql, 3,
                      ins_inc_types);
  res[4] = PQprepare (pg.conn, STMT_SEL_CHECKSUM, sel_sql, 1,
                      sel_types);
  res[5] = PQprepare (pg.conn, STMT_INS_INGEST, ins_ing_sql, 3,
                      ins_ing_types);
  res[6] = PQprepare (pg.conn, STMT_INS_AGG, ins_agg_sql, 3,
                      ins_agg_types);

  for (int i = 0; i < 7; i++)
    {
      if (res[i] == NULL || PQresultStatus (res[i]) != PGRES_COMMAND_OK)
        ok = false;
      if (res[i] != NULL)
        PQclear (res[i]);
    }

  return ok;
}

static bool
connect_and_prepare (void)
{
  PGresult *res;
  ExecStatusType st;

  if (pg.conn != NULL)
    {
      PQfinish (pg.conn);
      pg.conn = NULL;
    }
  pg.prepared = false;
  pg.schema_ok = false;

  pg.conn = PQconnectdb (pg.conninfo);
  if (pg.conn == NULL || PQstatus (pg.conn) != CONNECTION_OK)
    {
      note_pg_error ();
      if (pg.conn != NULL)
        {
          PQfinish (pg.conn);
          pg.conn = NULL;
        }
      return false;
    }

  /* Idempotent schema: the embedded copy of schema.sql, CREATE
   * TABLE IF NOT EXISTS only — existing data is never touched. */
  res = PQexec (pg.conn, dbt_schema_ddl ());
  st = res != NULL ? PQresultStatus (res) : PGRES_FATAL_ERROR;
  if (res != NULL)
    PQclear (res);
  if (st != PGRES_COMMAND_OK)
    {
      note_pg_error ();
      PQfinish (pg.conn);
      pg.conn = NULL;
      return false;
    }
  pg.schema_ok = true;

  if (!prepare_statements ())
    {
      note_pg_error ();
      PQfinish (pg.conn);
      pg.conn = NULL;
      pg.schema_ok = false;
      return false;
    }
  pg.prepared = true;
  return true;
}

/* Ensure the backend can serve: reconnect after a lost connection
 * (PLAN.md section 4: the translator retries and stays readable). */
static bool
ensure_connected (void)
{
  if (pg.conn != NULL && PQstatus (pg.conn) == CONNECTION_OK
      && pg.prepared)
    return true;
  return connect_and_prepare ();
}

/* ---------------------------------------------------------------------
 *  Result interpretation: expected constraints are statuses.
 * ------------------------------------------------------------------- */

/* Classify a failed statement.  SQLSTATE is the portable truth:
 *   23505 unique_violation   -> DBT_ST_DUPLICATE (training_data)
 *   23503 foreign_key_violation, 22P02/22P03 invalid_text,
 *   22003 numeric_out_of_range, 23502 not_null_violation
 *                           -> DBT_ST_INVALID (caller's row)
 *   anything else            -> the transport/server layer.
 */
static enum dbt_storage_status
classify_error (PGresult *res)
{
  const char *sqlstate = res != NULL
                           ? PQresultErrorField (res, PG_DIAG_SQLSTATE)
                           : NULL;

  if (sqlstate == NULL)
    {
      note_pg_error ();
      return DBT_ST_TRANSPORT;
    }
  if (strcmp (sqlstate, "23505") == 0)
    return DBT_ST_DUPLICATE;
  if (strcmp (sqlstate, "23503") == 0 || strcmp (sqlstate, "23502") == 0
      || strcmp (sqlstate, "22P02") == 0
      || strcmp (sqlstate, "22P03") == 0
      || strcmp (sqlstate, "22003") == 0)
    return DBT_ST_INVALID;
  note_pg_error ();
  return DBT_ST_TRANSPORT;
}

/* Run a prepared statement that returns a single id column.
 * On success returns DBT_ST_OK and stores the id. */
static enum dbt_storage_status
exec_prepared_id (const char *stmt, const char *const *values,
                  const int *lengths, int nparams, long long *id)
{
  PGresult *res;
  ExecStatusType st;
  enum dbt_storage_status out;

  if (!ensure_connected ())
    return DBT_ST_TRANSPORT;

  res = PQexecPrepared (pg.conn, stmt, nparams, values, lengths, NULL, 0);
  st = res != NULL ? PQresultStatus (res) : PGRES_FATAL_ERROR;

  if (st == PGRES_TUPLES_OK && res != NULL && PQntuples (res) == 1)
    {
      *id = strtoll (PQgetvalue (res, 0, 0), NULL, 10);
      out = DBT_ST_OK;
    }
  else if (st == PGRES_FATAL_ERROR || st == PGRES_NONFATAL_ERROR)
    out = classify_error (res);
  else
    {
      note_pg_error ();
      out = DBT_ST_TRANSPORT;
    }

  if (res != NULL)
    PQclear (res);
  return out;
}

/* The existing id behind a UNIQUE checksum violation. */
static enum dbt_storage_status
lookup_checksum (const char *checksum, long long *id)
{
  const char *values[1] = { checksum };
  const int lengths[1] = { 0 };
  PGresult *res;
  enum dbt_storage_status out;

  if (!ensure_connected ())
    return DBT_ST_TRANSPORT;

  res = PQexecPrepared (pg.conn, STMT_SEL_CHECKSUM, 1, values, lengths,
                        NULL, 0);
  if (res != NULL && PQresultStatus (res) == PGRES_TUPLES_OK)
    {
      if (PQntuples (res) == 1)
        {
          *id = strtoll (PQgetvalue (res, 0, 0), NULL, 10);
          out = DBT_ST_OK;
        }
      else
        {
          /* The constraint fired but the row vanished: the caller
           * is told what is certain — this is a duplicate. */
          *id = 0;
          out = DBT_ST_DUPLICATE;
        }
    }
  else
    {
      note_pg_error ();
      out = DBT_ST_TRANSPORT;
    }
  if (res != NULL)
    PQclear (res);
  return out;
}

/* ---------------------------------------------------------------------
 *  Public backend functions
 * ------------------------------------------------------------------- */

void
pg_init (const char *conninfo)
{
  snprintf (pg.conninfo, sizeof pg.conninfo, "%s",
            conninfo != NULL ? conninfo : "dbname=gnuai");
  /* Connect eagerly: at mount the schema must exist and the
   * statements must be ready, before the first write arrives. */
  connect_and_prepare ();
}

void
pg_shutdown (void)
{
  if (pg.conn != NULL)
    {
      PQfinish (pg.conn);
      pg.conn = NULL;
    }
  pg.prepared = false;
  pg.schema_ok = false;
}

enum dbt_storage_status
pg_insert_runs (const struct dbt_row_runs *row, long long *id)
{
  const char *values[3] =
    {
      row->descriptor,
      row->aggregate_strategy,
      row->final_output,        /* NULL: SQL NULL */
    };
  const int lengths[3] = { 0, 0, 0 };

  return exec_prepared_id (STMT_INS_RUNS, values, lengths, 3, id);
}

enum dbt_storage_status
pg_insert_run_instances (const struct dbt_row_instances *row,
                         long long *id)
{
  char run_id_buf[32];
  char seed_buf[32];
  char score_buf[48];
  const char *values[7];
  const int lengths[7] = { 0, 0, 0, 0, 0, 0, 0 };

  snprintf (run_id_buf, sizeof run_id_buf, "%lld", row->run_id);
  values[0] = run_id_buf;
  values[1] = row->topology;
  values[2] = NULL;
  if (row->has_seed)
    {
      snprintf (seed_buf, sizeof seed_buf, "%lld", row->seed);
      values[2] = seed_buf;
    }
  values[3] = row->input;
  values[4] = row->output;
  values[5] = NULL;
  if (row->has_score)
    {
      snprintf (score_buf, sizeof score_buf, "%.9g", row->score);
      values[5] = score_buf;
    }
  values[6] = row->status;

  return exec_prepared_id (STMT_INS_INSTANCES, values, lengths, 7, id);
}

enum dbt_storage_status
pg_insert_training_data (const struct dbt_row_training *row,
                         long long *id)
{
  char http_status_buf[16];
  const char *values[4];
  const int lengths[4] = { 0, 0, 0, 0 };
  enum dbt_storage_status st;

  values[0] = row->source_url;
  values[1] = NULL;
  if (row->has_http_status)
    {
      snprintf (http_status_buf, sizeof http_status_buf, "%ld",
                row->http_status);
      values[1] = http_status_buf;
    }
  values[2] = row->content;
  values[3] = row->checksum;

  st = exec_prepared_id (STMT_INS_TRAINING, values, lengths, 4, id);
  if (st == DBT_ST_DUPLICATE)
    {
      /* The constraint is a fact, not an error: give the caller
       * the id that already carries this checksum (PLAN.md 4). */
      long long existing = 0;
      enum dbt_storage_status lk = lookup_checksum (row->checksum,
                                                    &existing);

      *id = existing;
      if (lk == DBT_ST_TRANSPORT)
        return DBT_ST_TRANSPORT;
    }
  return st;
}

enum dbt_storage_status
pg_insert_incidents (const struct dbt_row_incident *row, long long *id)
{
  char run_id_buf[32];
  char inst_id_buf[32];
  const char *values[3];
  const int lengths[3] = { 0, 0, 0 };

  snprintf (run_id_buf, sizeof run_id_buf, "%lld", row->run_id);
  values[0] = run_id_buf;
  values[1] = NULL;
  if (row->has_instance_id)
    {
      snprintf (inst_id_buf, sizeof inst_id_buf, "%lld",
                row->instance_id);
      values[1] = inst_id_buf;
    }
  values[2] = row->kind;

  return exec_prepared_id (STMT_INS_INCIDENTS, values, lengths, 3, id);
}

/* ---------------------------------------------------------------------
 *  Read half (phase A3): dbt_select.
 *
 *  The SELECT list and the WHERE column come from frozen whitelists
 *  (the parser already checked the where column); only the values
 *  are parameters.  Rows are rendered as a JSON array body.
 * ------------------------------------------------------------------- */

/* Column kinds: NUM renders raw, TEXT is escaped, JSONB renders raw
 * (the server returns valid JSON), NULL stays null. */
enum sel_kind { SEL_NUM = 0, SEL_TEXT, SEL_JSONB };

struct sel_col
  {
    const char *name;
    enum sel_kind kind;
  };

static const struct sel_col sel_runs[] =
  {
    { "id", SEL_NUM }, { "started_at", SEL_TEXT },
    { "descriptor", SEL_JSONB }, { "aggregate_strategy", SEL_TEXT },
    { "final_output", SEL_JSONB }, { NULL, 0 }
  };
static const struct sel_col sel_instances[] =
  {
    { "id", SEL_NUM }, { "run_id", SEL_NUM }, { "topology", SEL_TEXT },
    { "seed", SEL_NUM }, { "input", SEL_JSONB }, { "output", SEL_JSONB },
    { "score", SEL_NUM }, { "status", SEL_TEXT }, { NULL, 0 }
  };
static const struct sel_col sel_incidents[] =
  {
    { "id", SEL_NUM }, { "run_id", SEL_NUM }, { "instance_id", SEL_NUM },
    { "kind", SEL_TEXT }, { "detected_at", SEL_TEXT }, { NULL, 0 }
  };
static const struct sel_col sel_training[] =
  {
    { "id", SEL_NUM }, { "source_url", SEL_TEXT },
    { "http_status", SEL_NUM }, { "checksum", SEL_TEXT }, { NULL, 0 }
  };
static const struct sel_col sel_ingest[] =
  {
    { "id", SEL_NUM }, { "source_url", SEL_TEXT },
    { "detected_at", SEL_TEXT }, { "status", SEL_TEXT },
    { "records_added", SEL_NUM }, { NULL, 0 }
  };
static const struct sel_col sel_agg[] =
  {
    { "id", SEL_NUM }, { "topology", SEL_TEXT }, { "weight", SEL_NUM },
    { "version", SEL_NUM }, { "updated_at", SEL_TEXT }, { NULL, 0 }
  };

/* Append S to OUT as a JSON string (with quotes, escaped). */
static size_t
append_json_string (char *out, size_t cap, size_t len, const char *s)
{
  size_t room = cap > len ? cap - len : 0;

  if (room < 2)
    return len;
  out[len++] = '"';
  room--;
  for (const unsigned char *p = (const unsigned char *) s;
       *p != '\0' && room > 6; p++)
    {
      char tmp[8];
      int n;

      switch (*p)
        {
        case '"':  n = snprintf (tmp, sizeof tmp, "\\\""); break;
        case '\\': n = snprintf (tmp, sizeof tmp, "\\\\"); break;
        case '\n': n = snprintf (tmp, sizeof tmp, "\\n"); break;
        case '\r': n = snprintf (tmp, sizeof tmp, "\\r"); break;
        case '\t': n = snprintf (tmp, sizeof tmp, "\\t"); break;
        default:
          if (*p < 0x20)
            n = snprintf (tmp, sizeof tmp, "\\u%04x", *p);
          else
            {
              tmp[0] = (char) *p;
              n = 1;
            }
          break;
        }
      memcpy (out + len, tmp, (size_t) n);
      len += (size_t) n;
      room -= (size_t) n;
    }
  if (room < 1)
    return len;
  out[len++] = '"';
  return len;
}

enum dbt_storage_status
pg_select (enum dbt_table table, const char *where_col,
           const char *where_val, bool where_is_num, long limit,
           char *out, size_t cap, long *count)
{
  static const char *const tbl_name[] =
    { "", "runs", "run_instances", "training_data", "incidents",
      "ingest_jobs", "aggregator_state" };
  const struct sel_col *cols;
  char sql[512];
  char limit_buf[24];
  const char *params[2];
  int nparams = 0;
  PGresult *res;
  enum dbt_storage_status st = DBT_ST_OK;
  size_t len = 0;
  long n;

  if (table <= DBT_TABLE_NONE || table > DBT_TABLE_AGGREGATOR_STATE)
    return DBT_ST_INVALID;

  switch (table)
    {
    case DBT_TABLE_RUNS:          cols = sel_runs; break;
    case DBT_TABLE_RUN_INSTANCES: cols = sel_instances; break;
    case DBT_TABLE_INCIDENTS:     cols = sel_incidents; break;
    case DBT_TABLE_INGEST_JOBS:   cols = sel_ingest; break;
    case DBT_TABLE_AGGREGATOR_STATE: cols = sel_agg; break;
    default:                      cols = sel_training; break;
    }

  /* Build the SELECT list from the whitelist. */
  {
    size_t off = 0;

    off += (size_t) snprintf (sql + off, sizeof sql - off, "SELECT ");
    for (int i = 0; cols[i].name != NULL && off < sizeof sql - 32; i++)
      {
        off += (size_t) snprintf (sql + off, sizeof sql - off, "%s%s",
                                  i > 0 ? ", " : "", cols[i].name);
      }
    off += (size_t) snprintf (sql + off, sizeof sql - off,
                              " FROM %s", tbl_name[table]);
    if (where_col != NULL)
      off += (size_t) snprintf (sql + off, sizeof sql - off,
                                " WHERE %s = $1", where_col);
    snprintf (sql + off, sizeof sql - off, " ORDER BY id LIMIT $%d",
              where_col != NULL ? 2 : 1);
  }

  snprintf (limit_buf, sizeof limit_buf, "%ld", limit);
  if (where_col != NULL)
    {
      params[0] = where_val;
      params[1] = limit_buf;
      nparams = 2;
    }
  else
    {
      params[0] = limit_buf;
      nparams = 1;
    }
  (void) where_is_num;   /* the column type is implied by the whitelist */

  if (!ensure_connected ())
    return DBT_ST_TRANSPORT;

  res = PQexecParams (pg.conn, sql, nparams, NULL, params, NULL, NULL, 0);
  if (res == NULL || PQresultStatus (res) != PGRES_TUPLES_OK)
    {
      note_pg_error ();
      if (res != NULL)
        PQclear (res);
      return DBT_ST_TRANSPORT;
    }

  n = PQntuples (res);
  *count = n;
  if (n == 0)
    {
      PQclear (res);
      return DBT_ST_EMPTY;
    }

  for (long r = 0; r < n && len < cap; r++)
    {
      int ncols = PQnfields (res);

      if (r > 0 && len < cap)
        out[len++] = ',';
      if (len < cap)
        out[len++] = '{';
      for (int c = 0; c < ncols && len < cap - 2; c++)
        {
          const char *v = PQgetvalue (res, r, c);
          bool isnull = PQgetisnull (res, r, c);

          if (c > 0)
            out[len++] = ',';
          len = append_json_string (out, cap, len, cols[c].name);
          if (len >= cap)
            break;
          out[len++] = ':';
          if (isnull)
            {
              if (len + 4 < cap)
                {
                  memcpy (out + len, "null", 4);
                  len += 4;
                }
            }
          else if (cols[c].kind == SEL_TEXT)
            len = append_json_string (out, cap, len, v);
          else
            {
              /* NUM and JSONB render raw */
              size_t vl = strlen (v);

              if (len + vl < cap)
                {
                  memcpy (out + len, v, vl);
                  len += vl;
                }
            }
        }
      if (len < cap)
        out[len++] = '}';
    }
  if (len < cap)
    out[len] = '\0';
  else
    out[cap - 1] = '\0';

  PQclear (res);
  return st;
}

enum dbt_storage_status
pg_insert_ingest (const struct dbt_row_ingest *row, long long *id)
{
  char nbuf[24];
  const char *values[3];
  const int lengths[3] = { 0, 0, 0 };

  snprintf (nbuf, sizeof nbuf, "%ld", row->records_added);
  values[0] = row->source_url;
  values[1] = row->status;
  values[2] = nbuf;
  return exec_prepared_id (STMT_INS_INGEST, values, lengths, 3, id);
}

enum dbt_storage_status
pg_insert_aggregator (const struct dbt_row_aggregator *row,
                      long long *id)
{
  char wbuf[32];
  char vbuf[24];
  const char *values[3];
  const int lengths[3] = { 0, 0, 0 };

  snprintf (wbuf, sizeof wbuf, "%.6f", row->weight);
  snprintf (vbuf, sizeof vbuf, "%ld", row->version);
  values[0] = row->topology;
  values[1] = wbuf;
  values[2] = vbuf;
  return exec_prepared_id (STMT_INS_AGG, values, lengths, 3, id);
}

bool
pg_connected (void)
{
  return pg.conn != NULL && PQstatus (pg.conn) == CONNECTION_OK;
}

bool
pg_schema_ok (void)
{
  return pg.schema_ok;
}

int
pg_server_version (void)
{
  return pg.conn != NULL ? PQserverVersion (pg.conn) : 0;
}
