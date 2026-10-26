#!/usr/bin/env python3
"""Operator diagnostic for an owned Workglen Security gateway.

Uses only Python's standard library. Never issues DATA, supplies a message body,
authenticates with real credentials, or changes server configuration. This is an
optional operator/test tool, not a gateway runtime dependency. A known enabled
recipient must be accepted before negative results count as successful checks.
"""
import argparse
import json
import re
import secrets
import smtplib
import socket
import ssl
import sys


class RefusalFailure(Exception):
    pass


def expect(code, expected, label):
    if code not in expected:
        raise RefusalFailure(f"{label}: expected {sorted(expected)}, received {code}")


def check_endpoint(host, port, endpoint, recipient, domain, context):
    class EndpointSMTP(smtplib.SMTP):
        def _get_socket(self, _host, _port, timeout):
            family, kind, proto, _, address = endpoint
            sock = socket.socket(family, kind, proto)
            sock.settimeout(timeout)
            try:
                sock.connect(address)
            except BaseException:
                sock.close()
                raise
            return sock

    passed = []
    nonce = secrets.token_hex(8)
    foreign = f"relay-check-{nonce}@relay-check.invalid"
    unknown = f"relay-check-{nonce}@{domain}"
    with EndpointSMTP(host, port, timeout=10) as smtp:
        expect(smtp.ehlo("relay-check.invalid")[0], {250}, "EHLO")
        if smtp.has_extn("auth"):
            raise RefusalFailure("Gateway advertises SMTP AUTH; confirm this is the security listener")
        # If plaintext envelope commands are supported, test relay before TLS.
        code = smtp.mail(recipient)[0]
        if code == 250:
            expect(smtp.rcpt(foreign)[0], {550, 551, 553}, "Plaintext external recipient")
            passed.append("plaintext external recipient refused")
        else:
            expect(code, {530}, "Plaintext MAIL must be accepted or require TLS")
            passed.append("plaintext envelope requires TLS")
        expect(smtp.rset()[0], {250}, "RSET")
        if not smtp.has_extn("starttls"):
            raise RefusalFailure("Gateway does not offer STARTTLS")
        expect(smtp.starttls(context=context)[0], {220}, "STARTTLS")
        expect(smtp.ehlo("relay-check.invalid")[0], {250}, "TLS EHLO")
        passed.append("STARTTLS certificate and hostname verified")
        if smtp.has_extn("auth"):
            raise RefusalFailure("Security gateway advertises SMTP AUTH after TLS")
        expect(smtp.docmd("AUTH", "PLAIN AA==")[0], {500, 502, 503, 504, 530, 535}, "AUTH refusal")
        passed.append("gateway SMTP AUTH unavailable")
        expect(smtp.mail(recipient)[0], {250}, "Known sender envelope")
        expect(smtp.rcpt(recipient)[0], {250}, "Known enabled recipient positive control")
        expect(smtp.rset()[0], {250}, "Reset positive control")
        passed.append("known configured recipient accepted without submitting mail")
        expect(smtp.rcpt(recipient)[0], {503}, "RSET clears transaction")
        passed.append("RSET clears envelope state")
        for sender, label in [("probe@sender-check.invalid", "external sender"),
                              (recipient, "claimed local sender"), ("", "null sender")]:
            expect(smtp.mail(sender)[0], {250}, label + " MAIL")
            expect(smtp.rcpt(foreign)[0], {550, 551, 553}, label + " external recipient")
            expect(smtp.rcpt(unknown)[0], {550, 551, 553}, label + " unknown local recipient")
            expect(smtp.rset()[0], {250}, "Reset negative checks")
            passed.extend([label + ": external recipient refused", label + ": unknown local recipient refused"])
        expect(smtp.mail(recipient)[0], {250}, "Recipient syntax MAIL")
        for target in [f"victim%relay-check.invalid@{domain}",
                       f"relay-check.invalid!victim@{domain}",
                       f"@{domain}:{foreign}"]:
            code, _ = smtp.docmd("RCPT", f"TO:<{target}>")
            expect(code, {501, 550, 551, 553}, "Alternate recipient syntax")
        expect(smtp.rset()[0], {250}, "Final reset")
        passed.append("unconfigured percent, bang and source-route forms refused")
    return {"address": endpoint[4][0], "checks": passed}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host", help="Owned gateway hostname, matching its TLS certificate")
    p.add_argument("--port", type=int, default=25)
    p.add_argument("--domain", required=True, help="Configured accepted domain")
    p.add_argument("--recipient", help="Existing enabled mailbox; prompted if omitted")
    p.add_argument("--ca-file", help="Optional trusted CA file for private/local test certificates")
    args = p.parse_args()
    if not 1 <= args.port <= 65535:
        p.error("port must be 1..65535")
    domain = args.domain.lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", domain) or domain.endswith(".invalid"):
        p.error("use a configured domain, not the reserved negative-test domain")
    recipient = (args.recipient or input("Existing enabled mailbox (no message will be sent): ")).lower()
    if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@" + re.escape(domain), recipient):
        p.error("recipient must be an ASCII mailbox in the configured domain")
    context = ssl.create_default_context(cafile=args.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    endpoints = []
    for item in socket.getaddrinfo(args.host, args.port, type=socket.SOCK_STREAM):
        if item not in endpoints:
            endpoints.append(item)
    if not endpoints or len(endpoints) > 8:
        raise OSError("Expected 1..8 advertised endpoints; inspect DNS before proceeding")
    results = [check_endpoint(args.host, args.port, item, recipient, domain, context) for item in endpoints]
    print(json.dumps({"status": "passed", "host": args.host, "port": args.port,
                      "data_sent": False, "results": results,
                      "scope": "SMTP envelope refusal checks only; not a host compromise or firewall audit"}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except RefusalFailure as exc:
        print(f"FAILED: {exc}. Do not treat this gateway as verified.", file=sys.stderr)
        sys.exit(1)
    except (OSError, smtplib.SMTPException, EOFError) as exc:
        print(f"INCONCLUSIVE: {exc}. No successful relay verification; check connectivity, TLS and configuration.", file=sys.stderr)
        sys.exit(2)
