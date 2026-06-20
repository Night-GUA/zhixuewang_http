"""Demo: Pure-HTTP zhixuewang login + score query.

Usage:
    python demo.py
    python demo.py --username 12345678 --password yourpassword

This script demonstrates the full login flow and fetches the latest exam scores.
"""

from __future__ import annotations

import argparse
import base64
import sys

from custom_provider import http_login


def query_scores(cookies: dict) -> None:
    """Use zhixuewang library to query scores with the obtained cookies."""
    try:
        from zhixuewang.account import login_cookie
    except ImportError:
        print("[Error] zhixuewang library not installed. Run: pip install zhixuewang")
        sys.exit(1)

    # Construct account from cookies
    if "uname" not in cookies and "loginUserName" in cookies:
        cookies["uname"] = base64.b64encode(
            cookies["loginUserName"].encode("utf-8")
        ).decode("utf-8")

    account = login_cookie(cookies)
    print(f"\n  Student: {account.name}")

    # Get exam list
    exams = list(account.get_exams())
    if not exams:
        print("  No exams found.")
        return

    # Show latest 5 exams
    print(f"\n  Recent exams (showing up to 5, use -a for all):")
    for i, exam in enumerate(exams[:5], 1):
        print(f"    {i}. {exam.name}")

    # Get latest exam scores
    marks = account.get_self_mark()
    if not marks:
        print("\n  No scores available for the latest exam.")
        return

    exam_name = getattr(marks[0].exam, "name", "Latest Exam") if hasattr(marks[0], "exam") else "Latest Exam"
    print(f"\n  Scores for: {exam_name}")
    print(f"  {'Subject':<12} {'Score':>8} {'Class Rank':>12} {'Grade Rank':>12}")
    print(f"  {'-'*12} {'-'*8} {'-'*12} {'-'*12}")

    total = 0.0
    count = 0
    for m in marks:
        name = getattr(m.subject, "name", "?")
        score = getattr(m, "score", None)
        class_rank = getattr(m, "class_rank", None)
        grade_rank = getattr(m, "grade_rank", None)

        score_str = f"{score:.1f}" if score is not None else "-"
        cr_str = str(class_rank) if class_rank is not None else "-"
        gr_str = str(grade_rank) if grade_rank is not None else "-"

        print(f"  {name:<12} {score_str:>8} {cr_str:>12} {gr_str:>12}")

        if isinstance(score, (int, float)):
            total += float(score)
            count += 1

    if count > 0:
        print(f"  {'-'*12} {'-'*8} {'-'*12} {'-'*12}")
        print(f"  {'Total':<12} {total:>8.1f}")


def main():
    parser = argparse.ArgumentParser(description="zhixuewang pure-HTTP login demo")
    parser.add_argument("-u", "--username", help="zhixue.com student ID or phone")
    parser.add_argument("-p", "--password", help="plaintext password")
    args = parser.parse_args()

    username = args.username or input("Username: ").strip()
    password = args.password or input("Password: ").strip()

    print(f"\nLogging in as {username} (pure HTTP, may take 30-60s)...\n")

    try:
        cookies = http_login(username, password, print_fn=print)
    except Exception as e:
        print(f"\n[FAILED] Login error: {e}")
        sys.exit(1)

    print(f"\n[OK] Login successful! Got {len(cookies)} cookies.")

    # Query scores
    print("\nQuerying scores...")
    try:
        query_scores(cookies)
    except Exception as e:
        print(f"\n[Error] Score query failed: {e}")


if __name__ == "__main__":
    main()
