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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.TimeStampTokenProductionComparator;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static eu.europa.esig.dss.enumerations.SignatureLevel.CAdES_BASELINE_LT;

/**
 * This class holds the CAdES-LT signature profiles
 *
 */
public class CAdESLevelBaselineLT extends CAdESLevelBaselineT {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESLevelBaselineLT.class);

	/**
	 * The default constructor.
	 *
	 * @param tspSource {@link TSPSource} for a timestamp creation
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public CAdESLevelBaselineLT(TSPSource tspSource, CertificateVerifier certificateVerifier) {
		super(tspSource, certificateVerifier);
	}

	@Override
	protected CMS extendCMSSignatures(CMS cms, CAdESSignatureParameters parameters,
									  List<String> signatureIdsToExtend) {
		cms = super.extendCMSSignatures(cms, parameters, signatureIdsToExtend);

		CMSDocumentAnalyzer documentAnalyzer = getDocumentValidator(cms, parameters);
		List<AdvancedSignature> signatures = documentAnalyzer.getSignatures();

		final List<AdvancedSignature> signaturesToExtend = getExtendToLTLevelSignatures(signatures, signatureIdsToExtend);
		if (Utils.isCollectionEmpty(signaturesToExtend)) {
			return cms;
		}

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker(parameters);
		if (CAdES_BASELINE_LT.equals(parameters.getSignatureLevel())) {
			signatureRequirementsChecker.assertExtendToLTLevelPossible(signaturesToExtend);
		}

		signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
		signatureRequirementsChecker.assertCertificateChainValidForLTLevel(signaturesToExtend);

		// Perform signatures validation
		ValidationDataContainer validationDataContainer = documentAnalyzer.getValidationData(signaturesToExtend);

		/*
		 * ETSI EN 319 122-1 V1.1.1 (2016-04), chapter "5.5.3 The archive-time-stamp-v3 attribute":
		 *
		 * The present document specifies two strategies for the inclusion of validation data,
		 * depending on whether attributes for long term availability, as defined in different
		 * versions of ETSI TS 101 733 [1], have already been added to the SignedData:
		 */
		if (includesATSv2(cms)) {
			/*
			 * - If an ATSv2, or other earlier form of archive time-stamp or a long-term-validation attribute, is
			 *   present in any SignerInfo of the root SignedData then the root SignedData.certificates and
			 *   SignedData.crls contents shall not be modified. The new validation material shall be provided within
			 *   the TimeStampToken of the latest archive time-stamp (which can be an ATSv2 as defined in
			 *   ETSI TS 101 733 [1], or an ATSv3) or within the latest long-term-validation attribute
			 *   (defined in ETSI TS 101 733 [1]) already contained in the SignerInfo ...
			 */
			final List<SignerInformation> newSignerInformationList = new ArrayList<>();
			for (AdvancedSignature signature : signatures) {
				final CAdESSignature cadesSignature = (CAdESSignature) signature;
				final SignerInformation signerInformation = cadesSignature.getSignerInformation();
				SignerInformation newSignerInformation = signerInformation;
				if (signaturesToExtend.contains(cadesSignature)) {
					ValidationData validationData = validationDataContainer.getAllValidationDataForSignatureForInclusion(cadesSignature);
					newSignerInformation = extendSignerInformation(signerInformation, validationData);
				}
				newSignerInformationList.add(newSignerInformation);
			}
			cms = replaceSigners(cms, newSignerInformationList);

		} else {
			/*
			 * - If none of ATSv2 attributes (see clause A.2.4), or an earlier form of archive time-stamp as defined in ETSI
			 *   TS 101 733 [1] or long-term-validation (see clause A.2.5) attributes is already present in any
			 *   SignerInfo of the root SignedData, then the new validation material shall be included within the root
			 *   SignedData.certificates, or SignedData.crls as applicable.
			 */
			ValidationData allValidationData = validationDataContainer.getAllValidationData();
			for (AdvancedSignature signature : signaturesToExtend) {
				allValidationData.excludeCertificateTokens(signature.getCertificateSource().getCertificates());
				allValidationData.excludeCRLTokens(signature.getCRLSource().getAllRevocationBinaries());
				allValidationData.excludeOCSPTokens(signature.getOCSPSource().getAllRevocationBinaries());
			}

			cms = extendWithValidationData(cms, allValidationData);
		}

		return cms;
	}

	private SignerInformation extendSignerInformation(SignerInformation signerInformation, ValidationData validationData) {
		AttributeTable unsignedAttributes = CAdESUtils.getUnsignedAttributes(signerInformation);
		unsignedAttributes = addValidationData(unsignedAttributes, validationData);
		return SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
	}
	
	private AttributeTable addValidationData(AttributeTable unsignedAttributes, ValidationData validationData) {
		TimeStampToken timestampTokenToExtend = getLastArchiveTimestamp(unsignedAttributes);
		if (timestampTokenToExtend != null) {
			CMS timestampCMS = CMSUtils.toCMS(timestampTokenToExtend);
			CMS extendedTimestampCMS = extendWithValidationData(timestampCMS, validationData);

			unsignedAttributes = replaceTimeStampAttribute(unsignedAttributes, timestampCMS, extendedTimestampCMS);
		}
		return unsignedAttributes;
	}

	private TimeStampToken getLastArchiveTimestamp(AttributeTable unsignedAttributes) {
		TimeStampToken lastTimeStampToken = null;
		TimeStampTokenProductionComparator comparator = new TimeStampTokenProductionComparator();
		for (TimeStampToken timeStampToken : CAdESUtils.findArchiveTimeStampTokens(unsignedAttributes)) {
			if (lastTimeStampToken == null || comparator.after(timeStampToken, lastTimeStampToken)) {
				lastTimeStampToken = timeStampToken;
			}
		}
		return lastTimeStampToken;
	}

	/**
	 * Returns a new {@code AttributeTable} with a replaced {@code attributeToReplace} by {@code attributeToAdd}
	 *
	 * @param attributeTable {@link AttributeTable} to replace value in
	 * @param attributeToReplace {@link CMS} to be replaced
	 * @param attributeToAdd {@link CMS} to replace by
	 * @return a new {@link AttributeTable}
	 */
	private AttributeTable replaceTimeStampAttribute(AttributeTable attributeTable, CMS attributeToReplace,
													 CMS attributeToAdd) {
		ASN1EncodableVector newAsn1EncodableVector = new ASN1EncodableVector();
		Attribute[] attributes = attributeTable.toASN1Structure().getAttributes();
		for (Attribute attribute : attributes) {
			Attribute newAttribute = attribute;
			if (CAdESUtils.isArchiveTimeStampToken(attribute)) {
				try {
					// ContentInfo binaries have to be compared, therefore CMS creation is required
					byte[] attributeValue = CAdESUtils.getEncodedValue(attribute);
					if (Arrays.equals(attributeToReplace.getEncoded(), attributeValue)) {
						ASN1Primitive asn1Primitive = DSSASN1Utils.toASN1Primitive(attributeToAdd.getEncoded());
						newAttribute = new Attribute(attribute.getAttrType(), new DERSet(asn1Primitive));
					}
				} catch (Exception e) {
					LOG.warn("Unable to build a CMS object from an unsigned attribute. Reason : {}", e.getMessage(), e);
					// we free to continue with the original object,
					// because it would not be possible to extend the attribute anyway
				}
			}
			newAsn1EncodableVector.add(newAttribute);
		}
		return new AttributeTable(newAsn1EncodableVector);
	}

	/**
	 * Extends the {@code cms} with the LT-level (validation data)
	 *
	 * @param cms {@link CMS} to extend
	 * @param validationDataForInclusion {@link ValidationData} to include
	 * @return extended {@link CMS}
	 */
	private CMS extendWithValidationData(CMS cms, ValidationData validationDataForInclusion) {
		final CMSBuilder cmsBuilder = new CMSBuilder().setOriginalCMS(cms);
		return cmsBuilder.extendCMSSignedData(validationDataForInclusion.getCertificateTokens(),
				validationDataForInclusion.getCrlTokens(), validationDataForInclusion.getOcspTokens());
	}

	/**
	 * Verifies if the CMS contains an ATSTv2
	 *
	 * @param cms {@link CMS} to check
	 * @return TRUE if the {@code cms} contains an ATSTv2, FALSE otherwise
	 */
	protected boolean includesATSv2(CMS cms) {
		for (SignerInformation signerInformation : cms.getSignerInfos()) {
			if (CAdESUtils.containsATSTv2(signerInformation)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a list of signatures to be extended according to th list of {@code signatureIdsToExtend}
	 *
	 * @param signatures a list of {@link AdvancedSignature}s
	 * @param signatureIdsToExtend a list of {@link String} signature identifiers to be extended
	 * @return a list of {@link AdvancedSignature}s
	 */
	protected List<AdvancedSignature> getExtendToLTLevelSignatures(List<AdvancedSignature> signatures, List<String> signatureIdsToExtend) {
		final List<AdvancedSignature> toBeExtended = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			if (signatureIdsToExtend.contains(signature.getId())) {
				toBeExtended.add(signature);
			}
		}
		return toBeExtended;
	}

}
