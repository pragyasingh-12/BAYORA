import initSqlJs, { Database } from "sql.js";
import * as fs from "fs";
import * as path from "path";

export interface EvaluationRecord {
  id: string;
  status: "created" | "running" | "completed" | "failed" | "killed";
  modelId: string;
  policyHash: string;
  datasetVersions: string; // JSON
  seed: number;
  redSuccessBefore: number | null;
  redSuccessAfter: number | null;
  n: number;
  createdAt: string;
  updatedAt: string;
}

export interface StoredProbeResult {
  id: string;
  command: string;
  exitCode: number;
  blocked: boolean;
  ts: string;
  outputLog?: string;
}

export class SQLiteDatabase {
  private db: Database | null = null;
  private dbPath: string;

  constructor() {
    const dataDir = path.resolve(process.cwd(), ".bayora");
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    this.dbPath = path.join(dataDir, "bayora.sqlite");
  }

  public async initialize(): Promise<void> {
    const SQL = await initSqlJs();
    if (fs.existsSync(this.dbPath)) {
      const fileBuffer = fs.readFileSync(this.dbPath);
      this.db = new SQL.Database(fileBuffer);
    } else {
      this.db = new SQL.Database();
    }

    this.createSchema();
  }

  private createSchema(): void {
    if (!this.db) return;

    this.db.run(`
      CREATE TABLE IF NOT EXISTS evaluations (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        model_id TEXT NOT NULL,
        policy_hash TEXT NOT NULL,
        dataset_versions TEXT NOT NULL,
        seed INTEGER NOT NULL,
        red_success_before REAL,
        red_success_after REAL,
        n INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_events (
        idx INTEGER PRIMARY KEY,
        id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        evaluation_id TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target_resource TEXT NOT NULL,
        canonical_payload TEXT NOT NULL,
        payload_summary TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS security_findings (
        id TEXT PRIMARY KEY,
        evaluation_id TEXT NOT NULL,
        tenant TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS probe_records (
        id TEXT PRIMARY KEY,
        command TEXT NOT NULL,
        exit_code INTEGER NOT NULL,
        blocked INTEGER NOT NULL,
        output_log TEXT,
        ts TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS checkpoints (
        id TEXT PRIMARY KEY,
        event_index INTEGER NOT NULL,
        chain_head TEXT NOT NULL,
        signature TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
    this.persist();
  }

  public persist(): void {
    if (!this.db) return;
    try {
      const data = this.db.export();
      const buffer = Buffer.from(data);
      fs.writeFileSync(this.dbPath, buffer);
    } catch (err) {
      console.error("[SQLiteDatabase] Failed to persist to disk:", err);
    }
  }

  // --- Evaluations ---
  public saveEvaluation(evalRecord: EvaluationRecord): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO evaluations 
      (id, status, model_id, policy_hash, dataset_versions, seed, red_success_before, red_success_after, n, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run([
      evalRecord.id,
      evalRecord.status,
      evalRecord.modelId,
      evalRecord.policyHash,
      evalRecord.datasetVersions,
      evalRecord.seed,
      evalRecord.redSuccessBefore,
      evalRecord.redSuccessAfter,
      evalRecord.n,
      evalRecord.createdAt,
      evalRecord.updatedAt,
    ]);
    stmt.free();
    this.persist();
  }

  public getEvaluation(id: string): EvaluationRecord | null {
    if (!this.db) return null;
    const stmt = this.db.prepare("SELECT * FROM evaluations WHERE id = ?");
    stmt.bind([id]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return {
        id: row.id as string,
        status: row.status as any,
        modelId: row.model_id as string,
        policyHash: row.policy_hash as string,
        datasetVersions: row.dataset_versions as string,
        seed: Number(row.seed),
        redSuccessBefore: row.red_success_before != null ? Number(row.red_success_before) : null,
        redSuccessAfter: row.red_success_after != null ? Number(row.red_success_after) : null,
        n: Number(row.n),
        createdAt: row.created_at as string,
        updatedAt: row.updated_at as string,
      };
    }
    stmt.free();
    return null;
  }

  public listEvaluations(): EvaluationRecord[] {
    if (!this.db) return [];
    const stmt = this.db.prepare("SELECT * FROM evaluations ORDER BY created_at DESC");
    const results: EvaluationRecord[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push({
        id: row.id as string,
        status: row.status as any,
        modelId: row.model_id as string,
        policyHash: row.policy_hash as string,
        datasetVersions: row.dataset_versions as string,
        seed: Number(row.seed),
        redSuccessBefore: row.red_success_before != null ? Number(row.red_success_before) : null,
        redSuccessAfter: row.red_success_after != null ? Number(row.red_success_after) : null,
        n: Number(row.n),
        createdAt: row.created_at as string,
        updatedAt: row.updated_at as string,
      });
    }
    stmt.free();
    return results;
  }

  public updateEvaluationStatus(id: string, status: EvaluationRecord["status"]): boolean {
    const ev = this.getEvaluation(id);
    if (!ev) return false;
    ev.status = status;
    ev.updatedAt = new Date().toISOString();
    this.saveEvaluation(ev);
    return true;
  }

  // --- Audit Events ---
  public insertAuditEvent(event: {
    idx: number;
    id: string;
    timestamp: string;
    evaluationId: string;
    actor: string;
    action: string;
    targetResource: string;
    canonicalPayload: string;
    payloadSummary: string;
    prevHash: string;
    hash: string;
  }): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO audit_events 
      (idx, id, timestamp, evaluation_id, actor, action, target_resource, canonical_payload, payload_summary, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run([
      event.idx,
      event.id,
      event.timestamp,
      event.evaluationId,
      event.actor,
      event.action,
      event.targetResource,
      event.canonicalPayload,
      event.payloadSummary,
      event.prevHash,
      event.hash,
    ]);
    stmt.free();
    this.persist();
  }

  public clearAuditEvents(): void {
    if (!this.db) return;
    this.db.run("DELETE FROM audit_events");
    this.persist();
  }

  public getAuditEvents(): any[] {
    if (!this.db) return [];
    const stmt = this.db.prepare("SELECT * FROM audit_events ORDER BY idx ASC");
    const events: any[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      events.push({
        index: Number(row.idx),
        id: row.id,
        timestamp: row.timestamp,
        evaluationId: row.evaluation_id,
        actor: row.actor,
        action: row.action,
        targetResource: row.target_resource,
        canonicalPayload: row.canonical_payload,
        payloadSummary: row.payload_summary,
        payloadHash: row.hash, // canonical payload hash
        prevHash: row.prev_hash,
        hash: row.hash,
      });
    }
    stmt.free();
    return events;
  }

  // --- Probe Records ---
  public saveProbeResult(probe: StoredProbeResult): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO probe_records (id, command, exit_code, blocked, output_log, ts)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run([
      probe.id,
      probe.command,
      probe.exitCode,
      probe.blocked ? 1 : 0,
      probe.outputLog || "",
      probe.ts,
    ]);
    stmt.free();
    this.persist();
  }

  public getLatestProbes(): StoredProbeResult[] {
    if (!this.db) return [];
    const stmt = this.db.prepare("SELECT * FROM probe_records ORDER BY ts DESC");
    const results: StoredProbeResult[] = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      results.push({
        id: row.id as string,
        command: row.command as string,
        exitCode: Number(row.exit_code),
        blocked: Boolean(row.blocked),
        outputLog: row.output_log as string,
        ts: row.ts as string,
      });
    }
    stmt.free();
    return results;
  }

  // --- Checkpoints ---
  public saveCheckpoint(chk: { id: string; eventIndex: number; chainHead: string; signature: string; publicKey: string; createdAt: string }): void {
    if (!this.db) return;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO checkpoints (id, event_index, chain_head, signature, public_key, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run([chk.id, chk.eventIndex, chk.chainHead, chk.signature, chk.publicKey, chk.createdAt]);
    stmt.free();
    this.persist();
  }

  public getLatestCheckpoint(): { id: string; eventIndex: number; chainHead: string; signature: string; publicKey: string; createdAt: string } | null {
    if (!this.db) return null;
    const stmt = this.db.prepare("SELECT * FROM checkpoints ORDER BY event_index DESC LIMIT 1");
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return {
        id: row.id as string,
        eventIndex: Number(row.event_index),
        chainHead: row.chain_head as string,
        signature: row.signature as string,
        publicKey: row.public_key as string,
        createdAt: row.created_at as string,
      };
    }
    stmt.free();
    return null;
  }
}

// Global Singleton instance
export const sqliteDb = new SQLiteDatabase();
