package eu.europa.ec.markt.dss.validation102853;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public enum TimestampValidity {

    NOT_YET_VERIFIED, // if the timestamp token is mathematically and structurally valid.
    VALID, // if the timestamp token is mathematically and structurally valid.
    NOT_VALID_STRUCTURE, // if an exception occurs in processing the token.
    NOT_VALID_SIGNATURE, // if the certificate or signature fail to be valid.
    NO_SIGNING_CERTIFICATE // if the sigVerifierProvider has no associated certificate.
}
