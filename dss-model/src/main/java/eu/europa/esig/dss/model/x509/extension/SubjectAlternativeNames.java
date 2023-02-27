package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

import java.util.List;

/**
 * 4.2.1.6.  Subject Alternative Name
 *    The subject alternative name extension allows identities to be bound
 *    to the subject of the certificate.  These identities may be included
 *    in addition to or in place of the identity in the subject field of
 *    the certificate.  Defined options include an Internet electronic mail
 *    address, a DNS name, an IP address, and a Uniform Resource Identifier
 *    (URI).  Other options exist, including completely local definitions.
 *    Multiple name forms, and multiple instances of each name form, MAY be
 *    included.  Whenever such identities are to be bound into a
 *    certificate, the subject alternative name (or issuer alternative
 *    name) extension MUST be used; however, a DNS name MAY also be
 *    represented in the subject field using the domainComponent attribute
 *    as described in Section 4.1.2.4.  Note that where such names are
 *    represented in the subject field implementations are not required to
 *    convert them into DNS names.
 */
public class SubjectAlternativeNames extends CertificateExtension {

    private static final long serialVersionUID = 1164359049003917189L;

    /** List of subject alternative names */
    private List<String> names;

    /**
     * Default constructor
     */
    public SubjectAlternativeNames() {
        super(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid());
    }

    /**
     * Returns a list of subject alternative names
     *
     * @return list of {@link String}s
     */
    public List<String> getNames() {
        return names;
    }

    /**
     * Sets a list of subject alternative names
     *
     * @param names list of {@link String}s
     */
    public void setNames(List<String> names) {
        this.names = names;
    }

}
