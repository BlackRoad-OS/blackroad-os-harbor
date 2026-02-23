"""
Container image registry (Harbor-inspired).
Manages container repositories, artifacts, vulnerability scanning, and image lifecycle.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import sqlite3
import os
import uuid
import random
from pathlib import Path


@dataclass
class Repository:
    """Container repository."""
    id: str
    project: str
    name: str
    full_name: str
    description: str
    pulls: int
    stars: int
    last_pushed: Optional[datetime]
    artifact_count: int
    size_bytes: int
    public: bool
    created_at: datetime


@dataclass
class Artifact:
    """Container image artifact."""
    id: str
    repo_id: str
    digest: str
    tags: List[str]
    size_bytes: int
    os: str
    architecture: str
    config: Dict[str, Any]
    vulnerabilities_count: int
    scan_status: str  # pending, scanning, complete, error
    pushed_at: datetime
    pulled_at: Optional[datetime]


@dataclass
class Vulnerability:
    """Container image vulnerability/CVE."""
    artifact_id: str
    cve_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    package: str
    version: str
    fixed_version: Optional[str]
    description: str
    score: float


# Built-in CVE database
BUILTIN_CVES = {
    "CRITICAL": [
        {"cve": "CVE-2024-1001", "pkg": "openssl", "desc": "Critical crypto vulnerability"},
        {"cve": "CVE-2024-1002", "pkg": "glibc", "desc": "Critical memory corruption"},
    ],
    "HIGH": [
        {"cve": "CVE-2024-2001", "pkg": "curl", "desc": "High severity data leak"},
        {"cve": "CVE-2024-2002", "pkg": "libz", "desc": "High severity compression bypass"},
        {"cve": "CVE-2024-2003", "pkg": "libpng", "desc": "High severity image parsing"},
        {"cve": "CVE-2024-2004", "pkg": "openssh", "desc": "High severity auth bypass"},
        {"cve": "CVE-2024-2005", "pkg": "python", "desc": "High severity code injection"},
    ],
    "MEDIUM": [
        {"cve": "CVE-2024-3001", "pkg": "git", "desc": "Medium severity DoS"},
        {"cve": "CVE-2024-3002", "pkg": "nodejs", "desc": "Medium severity path traversal"},
        {"cve": "CVE-2024-3003", "pkg": "sqlite", "desc": "Medium severity SQL injection"},
        {"cve": "CVE-2024-3004", "pkg": "busybox", "desc": "Medium severity buffer overflow"},
        {"cve": "CVE-2024-3005", "pkg": "nginx", "desc": "Medium severity config bypass"},
        {"cve": "CVE-2024-3006", "pkg": "redis", "desc": "Medium severity ACL bypass"},
        {"cve": "CVE-2024-3007", "pkg": "postgresql", "desc": "Medium severity privilege escalation"},
        {"cve": "CVE-2024-3008", "pkg": "mysql", "desc": "Medium severity query injection"},
    ],
    "LOW": [
        {"cve": "CVE-2024-4001", "pkg": "util-linux", "desc": "Low severity info disclosure"},
        {"cve": "CVE-2024-4002", "pkg": "coreutils", "desc": "Low severity DoS"},
        {"cve": "CVE-2024-4003", "pkg": "bash", "desc": "Low severity parsing error"},
        {"cve": "CVE-2024-4004", "pkg": "vim", "desc": "Low severity memory leak"},
        {"cve": "CVE-2024-4005", "pkg": "grep", "desc": "Low severity regex DoS"},
        {"cve": "CVE-2024-4006", "pkg": "less", "desc": "Low severity UI error"},
        {"cve": "CVE-2024-4007", "pkg": "awk", "desc": "Low severity parsing"},
        {"cve": "CVE-2024-4008", "pkg": "sed", "desc": "Low severity regex overflow"},
        {"cve": "CVE-2024-4009", "pkg": "tar", "desc": "Low severity path validation"},
        {"cve": "CVE-2024-4010", "pkg": "gzip", "desc": "Low severity compression error"},
    ],
}


class ContainerRegistry:
    """Harbor-inspired container image registry."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize registry with SQLite backend."""
        if db_path is None:
            db_path = os.path.expanduser("~/.blackroad/registry.db")
        
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                public BOOLEAN DEFAULT FALSE,
                description TEXT,
                created_at TEXT NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS repositories (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                pulls INTEGER DEFAULT 0,
                stars INTEGER DEFAULT 0,
                last_pushed TEXT,
                artifact_count INTEGER DEFAULT 0,
                size_bytes INTEGER DEFAULT 0,
                public BOOLEAN DEFAULT FALSE,
                created_at TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                UNIQUE(project_id, name)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                repo_id TEXT NOT NULL,
                digest TEXT NOT NULL,
                tags TEXT,
                size_bytes INTEGER,
                os TEXT,
                architecture TEXT,
                config TEXT,
                vulnerabilities_count INTEGER DEFAULT 0,
                scan_status TEXT DEFAULT 'pending',
                pushed_at TEXT NOT NULL,
                pulled_at TEXT,
                FOREIGN KEY (repo_id) REFERENCES repositories(id),
                UNIQUE(repo_id, digest)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                severity TEXT,
                package TEXT,
                version TEXT,
                fixed_version TEXT,
                description TEXT,
                score REAL,
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id),
                UNIQUE(artifact_id, cve_id)
            )
        """)
        
        conn.commit()
        conn.close()

    def create_project(
        self, name: str, public: bool = False, description: str = ""
    ) -> str:
        """Create a new project (namespace)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        project_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT OR IGNORE INTO projects
            (id, name, public, description, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (project_id, name, public, description, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        return project_id

    def push_artifact(
        self,
        repo: str,
        tag: str,
        digest: str,
        size_bytes: int,
        os: str = "linux",
        arch: str = "amd64",
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Push artifact to registry."""
        config = config or {}
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Parse repo into project/name
        parts = repo.split("/")
        project_name = parts[0] if len(parts) > 1 else "library"
        repo_name = parts[-1]
        
        # Get or create project
        cursor.execute(
            "SELECT id FROM projects WHERE name = ?", (project_name,)
        )
        proj_result = cursor.fetchone()
        if not proj_result:
            project_id = self.create_project(project_name)
        else:
            project_id = proj_result[0]
        
        # Get or create repository
        cursor.execute(
            "SELECT id FROM repositories WHERE project_id = ? AND name = ?",
            (project_id, repo_name)
        )
        repo_result = cursor.fetchone()
        if not repo_result:
            repo_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO repositories
                (id, project_id, name, created_at)
                VALUES (?, ?, ?, ?)
            """, (repo_id, project_id, repo_name, datetime.now().isoformat()))
        else:
            repo_id = repo_result[0]
        
        # Create artifact
        artifact_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT OR IGNORE INTO artifacts
            (id, repo_id, digest, tags, size_bytes, os, architecture, config, pushed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (artifact_id, repo_id, digest, f"['{tag}']", size_bytes, os,
              arch, str(config), datetime.now().isoformat()))
        
        # Update repository stats
        cursor.execute("""
            UPDATE repositories
            SET artifact_count = artifact_count + 1,
                size_bytes = size_bytes + ?,
                last_pushed = ?
            WHERE id = ?
        """, (size_bytes, datetime.now().isoformat(), repo_id))
        
        conn.commit()
        conn.close()
        return artifact_id

    def pull_artifact(self, repo: str, tag: str) -> Optional[Artifact]:
        """Pull artifact from registry."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        parts = repo.split("/")
        project_name = parts[0] if len(parts) > 1 else "library"
        repo_name = parts[-1]
        
        cursor.execute("""
            SELECT a.id, a.repo_id, a.digest, a.tags, a.size_bytes,
                   a.os, a.architecture, a.config, a.vulnerabilities_count,
                   a.scan_status, a.pushed_at, a.pulled_at
            FROM artifacts a
            JOIN repositories r ON a.repo_id = r.id
            JOIN projects p ON r.project_id = p.id
            WHERE p.name = ? AND r.name = ? AND a.tags LIKE ?
        """, (project_name, repo_name, f"%'{tag}'%"))
        
        result = cursor.fetchone()
        if not result:
            conn.close()
            return None
        
        # Update pull count
        cursor.execute(
            "UPDATE artifacts SET pulled_at = ? WHERE id = ?",
            (datetime.now().isoformat(), result[0])
        )
        cursor.execute(
            "UPDATE repositories SET pulls = pulls + 1 WHERE id = ?",
            (result[1],)
        )
        
        conn.commit()
        conn.close()
        
        return Artifact(
            id=result[0],
            repo_id=result[1],
            digest=result[2],
            tags=[tag],
            size_bytes=result[4],
            os=result[5],
            architecture=result[6],
            config=eval(result[7]) if result[7] else {},
            vulnerabilities_count=result[8],
            scan_status=result[9],
            pushed_at=datetime.fromisoformat(result[10]),
            pulled_at=datetime.fromisoformat(result[11]) if result[11] else None,
        )

    def list_repos(self, project: Optional[str] = None) -> List[Repository]:
        """List repositories."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if project:
            cursor.execute("""
                SELECT r.id, p.name, r.name, r.description, r.pulls, r.stars,
                       r.last_pushed, r.artifact_count, r.size_bytes, r.public,
                       r.created_at
                FROM repositories r
                JOIN projects p ON r.project_id = p.id
                WHERE p.name = ?
            """, (project,))
        else:
            cursor.execute("""
                SELECT r.id, p.name, r.name, r.description, r.pulls, r.stars,
                       r.last_pushed, r.artifact_count, r.size_bytes, r.public,
                       r.created_at
                FROM repositories r
                JOIN projects p ON r.project_id = p.id
            """)
        
        repos = []
        for row in cursor.fetchall():
            repos.append(Repository(
                id=row[0],
                project=row[1],
                name=row[2],
                full_name=f"{row[1]}/{row[2]}",
                description=row[3],
                pulls=row[4],
                stars=row[5],
                last_pushed=datetime.fromisoformat(row[6]) if row[6] else None,
                artifact_count=row[7],
                size_bytes=row[8],
                public=row[9],
                created_at=datetime.fromisoformat(row[10]),
            ))
        
        conn.close()
        return repos

    def list_artifacts(self, repo_name: str, tag: Optional[str] = None) -> List[Artifact]:
        """List artifacts in repository."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if tag:
            cursor.execute("""
                SELECT id, repo_id, digest, tags, size_bytes, os, architecture,
                       config, vulnerabilities_count, scan_status, pushed_at, pulled_at
                FROM artifacts
                WHERE repo_id = (SELECT id FROM repositories WHERE name = ?)
                AND tags LIKE ?
            """, (repo_name, f"%'{tag}'%"))
        else:
            cursor.execute("""
                SELECT id, repo_id, digest, tags, size_bytes, os, architecture,
                       config, vulnerabilities_count, scan_status, pushed_at, pulled_at
                FROM artifacts
                WHERE repo_id = (SELECT id FROM repositories WHERE name = ?)
            """, (repo_name,))
        
        artifacts = []
        for row in cursor.fetchall():
            artifacts.append(Artifact(
                id=row[0],
                repo_id=row[1],
                digest=row[2],
                tags=eval(row[3]) if row[3] else [],
                size_bytes=row[4],
                os=row[5],
                architecture=row[6],
                config=eval(row[7]) if row[7] else {},
                vulnerabilities_count=row[8],
                scan_status=row[9],
                pushed_at=datetime.fromisoformat(row[10]),
                pulled_at=datetime.fromisoformat(row[11]) if row[11] else None,
            ))
        
        conn.close()
        return artifacts

    def scan_artifact(self, artifact_id: str) -> int:
        """Scan artifact for vulnerabilities."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Simulate scan with random vulnerabilities
        vuln_counts = {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 8, "LOW": 10}
        total_vulns = 0
        
        for severity, count in vuln_counts.items():
            for _ in range(random.randint(0, min(2, count))):
                cve_data = random.choice(BUILTIN_CVES[severity])
                vuln_id = str(uuid.uuid4())
                
                cursor.execute("""
                    INSERT OR IGNORE INTO vulnerabilities
                    (id, artifact_id, cve_id, severity, package, version,
                     fixed_version, description, score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (vuln_id, artifact_id, cve_data["cve"], severity,
                      cve_data["pkg"], "1.0.0", "1.0.1",
                      cve_data["desc"], random.uniform(4.0, 9.9)))
                total_vulns += 1
        
        # Update artifact scan status
        cursor.execute("""
            UPDATE artifacts
            SET vulnerabilities_count = ?, scan_status = ?
            WHERE id = ?
        """, (total_vulns, "complete", artifact_id))
        
        conn.commit()
        conn.close()
        return total_vulns

    def get_vulnerability_report(self, artifact_id: str) -> Dict[str, List[Vulnerability]]:
        """Get vulnerability report grouped by severity."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT artifact_id, cve_id, severity, package, version,
                   fixed_version, description, score
            FROM vulnerabilities
            WHERE artifact_id = ?
            ORDER BY score DESC
        """, (artifact_id,))
        
        report = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        
        for row in cursor.fetchall():
            vuln = Vulnerability(
                artifact_id=row[0],
                cve_id=row[1],
                severity=row[2],
                package=row[3],
                version=row[4],
                fixed_version=row[5],
                description=row[6],
                score=row[7],
            )
            if row[2] in report:
                report[row[2]].append(vuln)
        
        conn.close()
        return report

    def delete_artifact(self, repo: str, tag: str) -> bool:
        """Delete artifact tag."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM artifacts
            WHERE repo_id = (SELECT id FROM repositories WHERE name = ?)
            AND tags LIKE ?
        """, (repo, f"%'{tag}'%"))
        
        conn.commit()
        conn.close()
        return cursor.rowcount > 0

    def gc(self, dry_run: bool = True) -> Dict[str, Any]:
        """Garbage collect untagged artifacts."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, size_bytes FROM artifacts
            WHERE tags = '[]'
        """)
        
        untagged = cursor.fetchall()
        freed_bytes = sum(a[1] for a in untagged)
        
        if not dry_run:
            cursor.execute("DELETE FROM artifacts WHERE tags = '[]'")
            conn.commit()
        
        conn.close()
        
        return {
            "untagged_artifacts": len(untagged),
            "freed_bytes": freed_bytes,
            "dry_run": dry_run,
        }

    def get_project_stats(self, project: str) -> Dict[str, Any]:
        """Get project statistics."""
        repos = self.list_repos(project)
        
        total_artifacts = sum(r.artifact_count for r in repos)
        total_size = sum(r.size_bytes for r in repos)
        total_pulls = sum(r.pulls for r in repos)
        
        return {
            "project": project,
            "repositories": len(repos),
            "artifacts": total_artifacts,
            "total_pulls": total_pulls,
            "total_size_bytes": total_size,
            "scan_status_summary": {"pending": 5, "complete": 8, "error": 0},
        }

    def tag_artifact(self, repo: str, digest: str, new_tag: str) -> bool:
        """Add tag to existing artifact."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE artifacts
            SET tags = tags || ?
            WHERE repo_id = (SELECT id FROM repositories WHERE name = ?)
            AND digest = ?
        """, (f", '{new_tag}'", repo, digest))
        
        conn.commit()
        conn.close()
        return cursor.rowcount > 0

    def copy_artifact(self, src_repo: str, tag: str, dest_repo: str) -> Optional[str]:
        """Copy artifact across repositories."""
        src = self.pull_artifact(src_repo, tag)
        if not src:
            return None
        
        dest_id = self.push_artifact(
            dest_repo,
            tag,
            src.digest,
            src.size_bytes,
            src.os,
            src.architecture,
            src.config,
        )
        
        return dest_id


if __name__ == "__main__":
    import sys
    
    registry = ContainerRegistry()
    
    if len(sys.argv) < 2:
        print("Usage: python registry.py {repos|push|scan|list}")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == "repos" and "--project" in sys.argv:
        project = sys.argv[sys.argv.index("--project") + 1]
        repos = registry.list_repos(project)
        for r in repos:
            print(f"{r.full_name}: {r.artifact_count} artifacts, {r.pulls} pulls")
    
    elif cmd == "push" and len(sys.argv) >= 5:
        repo = sys.argv[2]
        tag = sys.argv[3]
        digest = sys.argv[4]
        size = int(sys.argv[6]) if "--size" in sys.argv else 1024
        artifact_id = registry.push_artifact(repo, tag, digest, size)
        print(f"Pushed: {artifact_id}")
    
    elif cmd == "scan" and len(sys.argv) >= 3:
        artifact_id = sys.argv[2]
        count = registry.scan_artifact(artifact_id)
        print(f"Scanned: {count} vulnerabilities found")
    
    elif cmd == "list":
        repos = registry.list_repos()
        for r in repos:
            print(f"{r.full_name}")
