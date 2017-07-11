package eu.europa.dss.signature.policy;

/**
 * EnuRevReq  ::= ENUMERATED {
 *         clrCheck        (0),
 *                    -- Checks must be made against current CRLs
 *                    -- (or authority revocation lists)
 *         ocspCheck       (1),
 *                    -- The revocation status must be checked using
 *                    -- the Online Certificate Status Protocol (RFC 2450)
 *         bothCheck       (2),
 *                    -- Both CRL and OCSP checks must be carried out
 *         eitherCheck     (3),
 *                    -- At least one of CRL or OCSP checks must be
 *                    -- carried out
 *         noCheck         (4),
 *                    -- no check is mandated
 *         other           (5)
 *                    -- Other mechanism as defined by signature policy
 *                    -- extension
 *                                               }
 * @author davyd.santos
 *
 */
public enum EnuRevReq {
	crlCheck,
	ocspCheck,
	bothCheck,
	eitherCheck,
	noCheck,
	other;
}