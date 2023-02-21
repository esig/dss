package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

import java.util.List;

/**
 * 4.2.1.10. Name Constraints
 *    The name constraints extension, which MUST be used only in a CA
 *    certificate, indicates a name space within which all subject names in
 *    subsequent certificates in a certification path MUST be located.
 *    Restrictions apply to the subject distinguished name and apply to
 *    subject alternative names. Restrictions apply only when the
 *    specified name form is present. If no name of the type is in the
 *    certificate, the certificate is acceptable.
 */
public class NameConstraints extends CertificateExtension {

    /** Contains a list of subtrees that should match in the issued certificates */
    private List<GeneralSubtree> permittedSubtrees;

    /** Contains a list of subtrees that should be excluded from the issued certificate */
    private List<GeneralSubtree> excludedSubtrees;

    /**
     * Default constructor
     */
    public NameConstraints() {
        super(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid());
    }

    /**
     * Gets a list of permitted subtrees
     *
     * @return a list of {@link GeneralSubtree}s
     */
    public List<GeneralSubtree> getPermittedSubtrees() {
        return permittedSubtrees;
    }

    /**
     * Sets a list of permitted subtrees
     *
     * @param permittedSubtrees a list of {@link GeneralSubtree}s
     */
    public void setPermittedSubtrees(List<GeneralSubtree> permittedSubtrees) {
        this.permittedSubtrees = permittedSubtrees;
    }

    /**
     * Gets a list of excluded subtrees
     *
     * @return a list of {@link GeneralSubtree}s
     */
    public List<GeneralSubtree> getExcludedSubtrees() {
        return excludedSubtrees;
    }

    /**
     * Sets a list of excluded subtrees
     *
     * @param excludedSubtrees a list of {@link GeneralSubtree}s
     */
    public void setExcludedSubtrees(List<GeneralSubtree> excludedSubtrees) {
        this.excludedSubtrees = excludedSubtrees;
    }

}
