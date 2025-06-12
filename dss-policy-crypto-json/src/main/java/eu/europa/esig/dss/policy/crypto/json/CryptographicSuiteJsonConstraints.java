/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.policy.crypto.json;

/**
 * Contains a list of constraints for a JSON cryptographic suite as per ETSI TS 119 322.
 *
 */
public final class CryptographicSuiteJsonConstraints {

    /** Header name 'Algorithm' definition */
    public static final String ALGORITHM = "Algorithm";

    /** Header name 'AlgorithmIdentifier' definition */
    public static final String ALGORITHM_IDENTIFIER = "AlgorithmIdentifier";

    /** Header name 'Any' definition */
    public static final String ANY = "Any";

    /** Header name 'End' definition */
    public static final String END = "End";

    /** Header name 'Evaluation' definition */
    public static final String EVALUATION = "Evaluation";

    /** Header name 'Max' definition */
    public static final String MAX = "Max";

    /** Header name 'Min' definition */
    public static final String MIN = "Min";

    /** Header name 'name' definition */
    public static final String NAME = "name";

    /** Header name 'ObjectIdentifier' definition */
    public static final String OBJECT_IDENTIFIER = "ObjectIdentifier";

    /** Header name 'Parameter' definition */
    public static final String PARAMETER = "Parameter";

    /** Header name 'PolicyIssueDate' definition */
    public static final String POLICY_ISSUE_DATE = "PolicyIssueDate";

    /** Header name 'PolicyName' definition */
    public static final String POLICY_NAME = "PolicyName";

    /** SecuritySuitabilityPolicy */
    public static final String SECURITY_SUITABILITY_POLICY = "SecuritySuitabilityPolicy";

    /** Start */
    public static final String START = "Start";

    /** Header name 'URI' definition */
    public static final String URI = "URI";

    /** Header name 'Validity' definition */
    public static final String VALIDITY = "Validity";

    /**
     * Utils class
     */
    private CryptographicSuiteJsonConstraints() {
        // empty
    }

}
