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

	String STATUS = "Status";
	String SIGNING_CERTIFICATE = "SigningCertificate"; // constraint
	String CA_CERTIFICATE = "CACertificate"; //constraint
	String MAIN_SIGNATURE = "MainSignature"; // constraint
	String INDICATION = "Indication";
	String SUB_INDICATION = "SubIndication";

	// Returned by Basic Building Blocks process
	String VALIDATION_DATA = "ValidationData";
	// returned by Basic Validation Process
	String BASIC_VALIDATION_DATA = "BasicValidationData";

	String ADEST_VALIDATION_DATA = "AdESTValidationData";
	String PAST_CERT_VALIDATION_DATA = "PastCertValidationData";
	String PAST_SIGNATURE_VALIDATION_DATA = "PastSignatureValidationData";
	String LONG_TERM_VALIDATION_DATA = "LongTermValidationData";
	String CONTROL_TIME_SLIDING_DATA = "ControlTimeSlidingData";
	String TIMESTAMP_VALIDATION_DATA = "TimestampValidationData";

	String SIGNATURE = "Signature";
	String CONCLUSION = "Conclusion";
	String BASIC_BUILDING_BLOCKS = "BasicBuildingBlocks";
	String NAME = "Name";
	String ISC = "ISC";
	String VCI = "VCI";
	String XCV = "XCV";
	String CV = "CV";
	String SAV = "SAV";
	String IDENTIFIER = "Identifier";
	String POLICY = "Policy";
	String POLICY_NAME = "PolicyName";
	String POLICY_DESCRIPTION = "PolicyDescription";
	String NOTICE = "Notice";
	String INFO = "Info";
	String WARNING = "Warning";
	String ERROR = "Error";
	String CONSTRAINT = "Constraint";
	String SIGNING_TIME = "SigningTime";
	String TIMESTAMP = "Timestamp"; // node, constraint
	String SIGNED_SIGNATURE = "SignedSignature";
	String CONTENT_HINTS = "ContentHints";

	String SIMPLE_REPORT = "SimpleReport";
	String VALIDATION_TIME = "ValidationTime";
	String DOCUMENT_NAME = "DocumentName";
	String SIGNATURES_COUNT = "SignaturesCount";
	String VALID_SIGNATURES_COUNT = "ValidSignaturesCount";
	String SIGNATURE_FORMAT = "SignatureFormat";
	String SIGNATURE_LEVEL = "SignatureLevel";
	String SIGNED_BY = "SignedBy";

}
