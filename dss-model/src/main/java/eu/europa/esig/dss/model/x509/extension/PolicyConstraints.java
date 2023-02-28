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

/**
 * 4.2.1.11.  Policy Constraints
 *    The policy constraints extension can be used in certificates issued
 *    to CAs.  The policy constraints extension constrains path validation
 *    in two ways.  It can be used to prohibit policy mapping or require
 *    that each certificate in a path contain an acceptable policy
 *    identifier.
 */
public class PolicyConstraints extends CertificateExtension {

    /**
     * Indicates the number of additional certificates that may appear in the path before
     * an explicit policy is required for the entire path
     */
    private int requireExplicitPolicy = -1;

    /**
     * The value indicates the number of additional certificates that may appear in the path before
     * policy mapping is no longer permitted
     */
    private int inhibitPolicyMapping = -1;

    /**
     * Default constructor
     */
    public PolicyConstraints() {
        super(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid());
    }

    /**
     * Gets the requireExplicitPolicy constraint value
     *
     * @return requireExplicitPolicy int value if present, -1 otherwise
     */
    public int getRequireExplicitPolicy() {
        return requireExplicitPolicy;
    }

    /**
     * Sets the requireExplicitPolicy constraint value
     *
     * @param requireExplicitPolicy int value
     */
    public void setRequireExplicitPolicy(int requireExplicitPolicy) {
        this.requireExplicitPolicy = requireExplicitPolicy;
    }

    /**
     * Gets the inhibitPolicyMapping constraint value
     *
     * @return inhibitPolicyMapping int value if present, -1 otherwise
     */
    public int getInhibitPolicyMapping() {
        return inhibitPolicyMapping;
    }

    /**
     * Sets the inhibitPolicyMapping constraint value
     *
     * @param inhibitPolicyMapping int value
     */
    public void setInhibitPolicyMapping(int inhibitPolicyMapping) {
        this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

}
