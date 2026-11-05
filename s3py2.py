#!/usr/bin/env python3
"""
Reproduce: S3 UploadPart without Content-Length (chunked) -> 500 on Ozone 1.4
("Expected: 0 and actual N write sizes do not match").

Python 3.6+ standard library only - no curl, boto3 or aws-cli needed.

Usage:
  python3 mpu_chunked_repro.py --endpoint https://s3g:9879 --bucket BUCKET \
      [--access-key AK --secret-key SK] [--region us-east-1] \
      [--cacert /tmp/ca-bundle.crt | --insecure] [--size 1043]

Access/secret key default to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.
"""
import argparse
import datetime
import hashlib
import hmac
import http.client
import os
import re
import ssl
import sys
import time
import urllib.parse

UNSIGNED = "UNSIGNED-PAYLOAD"


def _q(s, safe="-_.~"):
    return urllib.parse.quote(s, safe=safe)


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


class S3:
    def __init__(self, endpoint, ak, sk, region, cacert, insecure):
        u = urllib.parse.urlsplit(endpoint)
        self.https = u.scheme == "https"
        self.host = u.hostname
        self.port = u.port or (443 if self.https else 80)
        self.host_header = u.netloc
        self.ak, self.sk, self.region = ak, sk, region
        self.ctx = None
        if self.https:
            self.ctx = ssl.create_default_context(cafile=cacert)
            if insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE

    def _conn(self):
        if self.https:
            return http.client.HTTPSConnection(self.host, self.port,
                                               context=self.ctx, timeout=60)
        return http.client.HTTPConnection(self.host, self.port, timeout=60)

    def _sign(self, method, path, query, payload_hash):
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        day = now.strftime("%Y%m%d")
        canon_query = "&".join(
            "%s=%s" % (_q(k), _q(v)) for k, v in sorted(query.items()))
        headers = {
            "host": self.host_header,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        signed = ";".join(sorted(headers))
        canon_headers = "".join(
            "%s:%s\n" % (k, headers[k]) for k in sorted(headers))
        canon_req = "\n".join([method, _q(path, safe="/-_.~"), canon_query,
                               canon_headers, signed, payload_hash])
        scope = "%s/%s/s3/aws4_request" % (day, self.region)
        to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                             hashlib.sha256(canon_req.encode()).hexdigest()])
        k = _hmac(("AWS4" + self.sk).encode(), day)
        k = _hmac(k, self.region)
        k = _hmac(k, "s3")
        k = _hmac(k, "aws4_request")
        sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, "
            "Signature=%s" % (self.ak, scope, signed, sig))
        url = _q(path, safe="/-_.~")
        if canon_query:
            url += "?" + canon_query
        return url, headers

    def request(self, method, path, query=None, body=None, chunked=False):
        query = query or {}
        if isinstance(body, bytes) and not chunked:
            payload_hash = hashlib.sha256(body).hexdigest()
        elif body is None:
            payload_hash = hashlib.sha256(b"").hexdigest()
        else:
            payload_hash = UNSIGNED
        url, headers = self._sign(method, path, query, payload_hash)
        conn = self._conn()
        try:
            if chunked:
                data = body

                def gen():
                    # several chunks, like a real streaming client
                    for i in range(0, len(data), 400):
                        yield data[i:i + 400]

                headers["transfer-encoding"] = "chunked"
                conn.request(method, url, body=gen(), headers=headers,
                             encode_chunked=True)
            else:
                conn.request(method, url, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()


def etag_of(headers):
    for k, v in headers.items():
        if k.lower() == "etag":
            return v
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--key", default="diag-repro-%d.parquet" % time.time())
    p.add_argument("--access-key", default=os.environ.get("AWS_ACCESS_KEY_ID"))
    p.add_argument("--secret-key",
                   default=os.environ.get("AWS_SECRET_ACCESS_KEY"))
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--cacert", default=os.environ.get("AWS_CA_BUNDLE"))
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--size", type=int, default=1043)
    p.add_argument("--put-check", action="store_true",
                   help="only send a chunked PutObject and report which "
                        "S3G code handled it")
    a = p.parse_args()
    if not a.access_key or not a.secret_key:
        sys.exit("need --access-key/--secret-key or AWS_* env vars")

    s3 = S3(a.endpoint, a.access_key, a.secret_key, a.region,
            a.cacert, a.insecure)
    path = "/%s/%s" % (a.bucket, a.key)
    data = os.urandom(a.size)

    if a.put_check:
        # Chunked PutObject is still rejected after the fix (only multipart
        # parts may have an unknown size), so the response code tells
        # which code is running and whether the body arrived chunked.
        print("== PutObject chunked, NO Content-Length (fingerprint)")
        st, _, body = s3.request("PUT", path, None, data, chunked=True)
        text = body.decode(errors="replace")
        print("HTTP %d" % st)
        if text:
            print(text)
        if st == 400 and "IncompleteBody" in text:
            print("RESULT: PATCHED S3G, request arrived chunked")
        elif st == 500:
            print("RESULT: STOCK S3G, request arrived chunked")
        elif st == 200:
            s3.request("DELETE", path)
            print("RESULT: body did NOT arrive chunked - something in front "
                  "of S3G added Content-Length; MPU result proves nothing")
        else:
            print("RESULT: unexpected response")
        return

    print("== initiate MPU for %s" % path)
    st, _, body = s3.request("POST", path, {"uploads": ""})
    m = re.search(rb"<UploadId>(.*?)</UploadId>", body)
    if st != 200 or not m:
        sys.exit("initiate failed: HTTP %d %s" % (st, body.decode(errors="replace")))
    upload_id = m.group(1).decode()
    print("uploadId=%s" % upload_id)
    q = {"partNumber": "1", "uploadId": upload_id}

    print("== part 1 WITH Content-Length (control)")
    st, _, body = s3.request("PUT", path, q, data)
    print("HTTP %d" % st)
    if st != 200:
        print(body.decode(errors="replace"))

    print("== part 1 chunked, NO Content-Length (the bug)")
    st, h, body = s3.request("PUT", path, q, data, chunked=True)
    print("HTTP %d" % st)
    etag = etag_of(h)
    if st != 200:
        print(body.decode(errors="replace"))
        print("RESULT: BUG PRESENT (chunked UploadPart rejected)")
        s3.request("DELETE", path, {"uploadId": upload_id})
        sys.exit(1)

    print("== complete MPU and read back")
    xml = ("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
           "<ETag>%s</ETag></Part></CompleteMultipartUpload>" % etag).encode()
    st, _, body = s3.request("POST", path, {"uploadId": upload_id}, xml)
    print("complete HTTP %d" % st)
    if st != 200:
        print(body.decode(errors="replace"))
        sys.exit(1)
    st, _, got = s3.request("GET", path)
    if st == 200 and got == data:
        print("DATA OK (%d bytes)" % len(got))
        print("RESULT: FIXED")
    else:
        print("GET HTTP %d, DATA MISMATCH (%d bytes)" % (st, len(got)))
        sys.exit(1)


if __name__ == "__main__":
    main()

