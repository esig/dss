/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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

    private static final long serialVersionUID = -1598798674152749825L;

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
