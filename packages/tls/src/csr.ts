/**
 * PKCS#10 CSR 생성(zero-dep) — ACME finalize에 제출. ECDSA P-256 + SHA-256.
 * extensionRequest 속성으로 SAN을 실어 다중 도메인 인증서를 요청한다.
 */
import { createSign } from "node:crypto";
import * as A from "./asn1.ts";
import { OID, distinguishedName, generateEcKeyPair, subjectAltNames } from "./x509.ts";

const OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";

export interface GeneratedCsr {
  /** CSR용으로 새로 생성한 인증서 개인키(PKCS#8 PEM). */
  keyPem: string;
  /** CSR DER(ACME finalize는 base64url). */
  csrDer: Uint8Array;
}

/** domains의 SAN을 담은 CSR + 새 키 생성. CN=domains[0]. */
export function generateCsr(domains: readonly string[]): GeneratedCsr {
  if (domains.length === 0) throw new Error("CSR: 도메인 최소 1개 필요");
  const kp = generateEcKeyPair();
  const subject = distinguishedName(domains[0]!);

  // extensionRequest 속성: Attribute{ OID, SET{ SEQUENCE OF Extension } }, Extension=SAN
  const sanExtension = A.seq(A.oid(OID.san), A.octetString(subjectAltNames(domains)));
  const extReqAttr = A.seq(A.oid(OID_EXTENSION_REQUEST), A.set(A.seq(sanExtension)));
  const attributes = A.context(0, true, extReqAttr); // [0] IMPLICIT Attributes(SET OF)

  const cri = A.seq(A.int(0), subject, A.raw(kp.spkiDer), attributes); // CertificationRequestInfo
  const signature = createSign("SHA256").update(Buffer.from(cri)).sign(kp.privateKeyPemForSign);
  const sigAlg = A.seq(A.oid(OID.ecdsaWithSHA256));
  const csr = A.seq(cri, sigAlg, A.bitString(new Uint8Array(signature)));
  return { keyPem: kp.privateKeyPem, csrDer: csr };
}
