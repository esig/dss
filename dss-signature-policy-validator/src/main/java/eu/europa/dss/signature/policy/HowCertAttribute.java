package eu.europa.dss.signature.policy;

/**
 * HowCertAttribute ::= ENUMERATED {
 *         claimedAttribute       (0),
 *         certifiedAttribtes     (1),
 *         either                 (2) }
 * @author davyd.santos
 *
 */
public enum HowCertAttribute {
	claimedAttribute,
	certifiedAttribtes,
	either;
}
