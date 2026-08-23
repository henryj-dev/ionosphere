/**
 * 셀프사인 X.509 v3 인증서 생성(zero-dep) — ECDSA P-256 + SHA-256.
 * SubjectPublicKeyInfo/서명은 node:crypto가 만들고, TBSCertificate DER은 asn1.ts로 조립한다.
 * ACME용 CSR(csr.ts)과 OID/이름 인코딩을 공유한다.
 */
import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import * as A from "./asn1.ts";

const enc = new TextEncoder();

export const OID = {
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
  commonName: "2.5.4.3",
  san: "2.5.29.17",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  serverAuth: "1.3.6.1.5.5.7.3.1",
} as const;

/** Name ::= SEQUENCE OF RDN(SET OF AttributeTypeAndValue) — CN 하나. */
export function distinguishedName(commonName: string): Uint8Array {
  return A.seq(A.set(A.seq(A.oid(OID.commonName), A.utf8String(commonName))));
}

/** GeneralNames ::= SEQUENCE OF dNSName [2] IMPLICIT IA5String. */
export function subjectAltNames(dnsNames: readonly string[]): Uint8Array {
  return A.seq(...dnsNames.map((d) => A.context(2, false, enc.encode(d))));
}

export interface EcKeyPair {
  privateKeyPem: string;
  /** SubjectPublicKeyInfo DER(그대로 인증서/CSR에 임베드). */
  spkiDer: Uint8Array;
  privateKeyPemForSign: string; // sign()에 넘길 PKCS#8 PEM
}

export function generateEcKeyPair(): EcKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return { privateKeyPem, spkiDer: new Uint8Array(publicKey.export({ type: "spki", format: "der" }) as Buffer), privateKeyPemForSign: privateKeyPem };
}

export interface SelfSignedOptions {
  commonName: string;
  sans?: string[];
  days?: number;
  notBefore?: Date;
}

export interface GeneratedCert {
  keyPem: string;
  certPem: string;
}

/** 셀프사인 인증서 + 키 생성. sans 미지정 시 commonName 하나를 SAN으로. */
export function generateSelfSigned(opts: SelfSignedOptions): GeneratedCert {
  const kp = generateEcKeyPair();
  const sigAlg = A.seq(A.oid(OID.ecdsaWithSHA256));
  const dn = distinguishedName(opts.commonName);
  const notBefore = opts.notBefore ?? new Date(Date.now() - 60_000); // 시계 오차 여유
  const notAfter = new Date(notBefore.getTime() + (opts.days ?? 825) * 86_400_000);
  const sans = opts.sans && opts.sans.length > 0 ? opts.sans : [opts.commonName];

  // keyUsage: digitalSignature(bit0) + keyEncipherment(bit2) → 0b10100000, unused 5
  const keyUsageBits = A.bitString(Uint8Array.of(0b10100000), 5);
  const extensions = A.context(
    3,
    true,
    A.seq(
      A.seq(A.oid(OID.basicConstraints), A.boolean(true), A.octetString(A.seq())), // cA:FALSE(빈 SEQ)
      A.seq(A.oid(OID.keyUsage), A.boolean(true), A.octetString(keyUsageBits)),
      A.seq(A.oid(OID.extKeyUsage), A.octetString(A.seq(A.oid(OID.serverAuth)))),
      A.seq(A.oid(OID.san), A.octetString(subjectAltNames(sans))),
    ),
  );

  const tbs = A.seq(
    A.context(0, true, A.int(2)), // version v3
    A.int(randomBytes(16)), // serialNumber(양수)
    sigAlg, // signature algid
    dn, // issuer = subject(셀프사인)
    A.seq(A.time(notBefore), A.time(notAfter)), // validity
    dn, // subject
    A.raw(kp.spkiDer), // subjectPublicKeyInfo
    extensions,
  );

  const signature = createSign("SHA256").update(Buffer.from(tbs)).sign(kp.privateKeyPemForSign);
  const cert = A.seq(tbs, sigAlg, A.bitString(new Uint8Array(signature)));
  return { keyPem: kp.privateKeyPem, certPem: A.toPem(cert, "CERTIFICATE") };
}
