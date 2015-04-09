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
package eu.europa.esig.dss.validation.policy.rules;

public interface NodeName {

    public static final String STATUS = "Status";
    public static final String SIGNING_CERTIFICATE = "SigningCertificate"; // constraint
    public static final String CA_CERTIFICATE = "CACertificate"; //constraint
    public static final String MAIN_SIGNATURE = "MainSignature"; // constraint
    public static final String INDICATION = "Indication";
    public static final String SUB_INDICATION = "SubIndication";

    // Returned by Basic Building Blocks process
    public static final String VALIDATION_DATA = "ValidationData";
    // returned by Basic Validation Process
    public static final String BASIC_VALIDATION_DATA = "BasicValidationData";

    public static final String ADEST_VALIDATION_DATA = "AdESTValidationData";
    public static final String PAST_CERT_VALIDATION_DATA = "PastCertValidationData";
    public static final String PAST_SIGNATURE_VALIDATION_DATA = "PastSignatureValidationData";
    public static final String LONG_TERM_VALIDATION_DATA = "LongTermValidationData";
    public static final String CONTROL_TIME_SLIDING_DATA = "ControlTimeSlidingData";
    public static final String TIMESTAMP_VALIDATION_DATA = "TimestampValidationData";

    public static final String SIGNATURE = "Signature";
    public static final String CONCLUSION = "Conclusion";
    public static final String BASIC_BUILDING_BLOCKS = "BasicBuildingBlocks";
    public static final String NAME = "Name";
    public static final String ISC = "ISC";
    public static final String VCI = "VCI";
    public static final String XCV = "XCV";
    public static final String CV = "CV";
    public static final String SAV = "SAV";
    public static final String IDENTIFIER = "Identifier";
    public static final String POLICY = "Policy";
    public static final String POLICY_NAME = "PolicyName";
    public static final String POLICY_DESCRIPTION = "PolicyDescription";
    public static final String NOTICE = "Notice";
    public static final String INFO = "Info";
    public static final String WARNING = "Warning";
    public static final String ERROR = "Error";
    public static final String CONSTRAINT = "Constraint";
    public static final String SIGNING_TIME = "SigningTime";
    public static final String TIMESTAMP = "Timestamp"; // node, constraint
    public static final String SIGNED_SIGNATURE = "SignedSignature";
    public static final String CONTENT_HINTS = "ContentHints";

    public static final String SIMPLE_REPORT = "SimpleReport";
    public static final String VALIDATION_TIME = "ValidationTime";
    public static final String DOCUMENT_NAME = "DocumentName";
    public static final String SIGNATURES_COUNT = "SignaturesCount";
    public static final String VALID_SIGNATURES_COUNT = "ValidSignaturesCount";
    public static final String SIGNATURE_FORMAT = "SignatureFormat";
    public static final String SIGNATURE_LEVEL = "SignatureLevel";
    public static final String SIGNED_BY = "SignedBy";
}
