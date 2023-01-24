package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

import java.util.List;

/**
 * 4.2.1.4.  Certificate Policies
 *    The certificate policies extension contains a sequence of one or more
 *    policy information terms, each of which consists of an object
 *    identifier (OID) and optional qualifiers.  Optional qualifiers, which
 *    MAY be present, are not expected to change the definition of the
 *    policy.  A certificate policy OID MUST NOT appear more than once in a
 *    certificate policies extension.
 */
public class CertificatePolicies extends CertificateExtension {

    /** List of certificate policies */
    private List<CertificatePolicy> policyList;

    /**
     * Default constructor
     */
    public CertificatePolicies() {
        super(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid());
    }

    /**
     * Returns the list of certificate policies
     *
     * @return a list of {@link CertificatePolicy}
     */
    public List<CertificatePolicy> getPolicyList() {
        return policyList;
    }

    /**
     * Sets a list of certificate policies
     *
     * @param policyList a list of {@link CertificatePolicy}
     */
    public void setPolicyList(List<CertificatePolicy> policyList) {
        this.policyList = policyList;
    }

}
