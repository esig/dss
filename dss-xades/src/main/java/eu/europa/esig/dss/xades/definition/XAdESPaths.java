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
package eu.europa.esig.dss.xades.definition;

import eu.europa.esig.dss.DSSNamespace;

public interface XAdESPaths {

	DSSNamespace getNamespace();

	String getSignedPropertiesUri();

	String getCounterSignatureUri();

	// ----------------------- From Object

	String getQualifyingPropertiesPath();

	String getSignedPropertiesPath();

	String getSignedSignaturePropertiesPath();

	String getSigningTimePath();

	String getSigningCertificatePath();

	String getSigningCertificateV2Path();

	String getSignatureProductionPlacePath();

	String getSignatureProductionPlaceV2Path();

	String getSignedDataObjectPropertiesPath();

	String getDataObjectFormatMimeType();

	String getDataObjectFormatObjectIdentifier();

	String getCommitmentTypeIndicationPath();

	String getUnsignedPropertiesPath();

	String getUnsignedSignaturePropertiesPath();

	String getCounterSignaturePath();

	String getAttributeRevocationRefsPath();

	String getCompleteRevocationRefsPath();

	String getCompleteCertificateRefsPath();

	String getCompleteCertificateRefsCertPath();

	String getCompleteCertificateRefsV2Path();

	String getCompleteCertificateRefsV2CertPath();

	String getAttributeCertificateRefsPath();

	String getAttributeCertificateRefsCertPath();

	String getAttributeCertificateRefsV2Path();

	String getAttributeCertificateRefsV2CertPath();

	String getCertificateValuesPath();

	String getRevocationValuesPath();

	String getAttributeRevocationValuesPath();

	String getTimeStampValidationDataRevocationValuesPath();

	String getSignatureTimestampsPath();

	String getSigAndRefsTimestampPath();

	String getSigAndRefsTimestampV2Path();

	String getSignaturePolicyIdentifier();

	String getEncapsulatedCertificateValuesPath();

	String getEncapsulatedAttrAuthoritiesCertValuesPath();

	String getEncapsulatedTimeStampValidationDataCertValuesPath();

	String getClaimedRolePath();

	String getClaimedRoleV2Path();

	String getCertifiedRolePath();

	String getCertifiedRoleV2Path();

	// ----------------

	String getCurrentCRLValuesChildren();

	String getCurrentCRLRefsChildren();

	String getCurrentOCSPValuesChildren();

	String getCurrentOCSPRefsChildren();

	String getCurrentOCSPRefResponderID();

	String getCurrentOCSPRefResponderIDByName();

	String getCurrentOCSPRefResponderIDByKey();

	String getCurrentOCSPRefProducedAt();

	String getCurrentDigestAlgAndValue();

	String getCurrentCertRefsCertChildren();

	String getCurrentCertChildren();

	String getCurrentCertDigest();

	String getCurrentEncapsulatedTimestamp();

	String getCurrentEncapsulatedCertificate();

	String getCurrentCertificateValuesEncapsulatedCertificate();

	String getCurrentRevocationValuesEncapsulatedOCSPValue();

	String getCurrentEncapsulatedOCSPValue();

	String getCurrentRevocationValuesEncapsulatedCRLValue();

	String getCurrentEncapsulatedCRLValue();

	String getCurrentIssuerSerialIssuerNamePath();

	String getCurrentIssuerSerialSerialNumberPath();

	String getCurrentIssuerSerialV2Path();

	String getCurrentCommitmentIdentifierPath();

	// --------------------------- Policy

	String getCurrentSignaturePolicyId();

	String getCurrentSignaturePolicyDigestAlgAndValue();

	String getCurrentSignaturePolicySPURI();

	String getCurrentSignaturePolicyDescription();

	String getCurrentSignaturePolicyImplied();

	String getCurrentInclude();

	String getCurrentQualifyingPropertiesPath();

}
