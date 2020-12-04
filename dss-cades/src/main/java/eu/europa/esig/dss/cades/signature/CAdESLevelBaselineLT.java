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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import eu.europa.esig.dss.validation.ValidationDataForInclusionBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import java.util.List;

/**
 * This class holds the CAdES-LT signature profiles
 *
 */
public class CAdESLevelBaselineLT extends CAdESLevelBaselineT {

	/** The CertificateVerifier to use */
	private final CertificateVerifier certificateVerifier;


	/**
	 * The default constructor.
	 *
	 * @param tspSource {@link TSPSource} for a timestamp creation
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public CAdESLevelBaselineLT(TSPSource tspSource, CertificateVerifier certificateVerifier) {
		super(tspSource);
		this.certificateVerifier = certificateVerifier;
	}

	@Override
	protected SignerInformation extendSignerInformation(CMSSignedData cmsSignedData, SignerInformation signerInformation, CAdESSignatureParameters parameters)
			throws DSSException {
		// add a LT level or replace an existing LT level
		CAdESSignature cadesSignature = newCAdESSignature(cmsSignedData, signerInformation, parameters.getDetachedContents());

		// add T level if needed
		if (Utils.isCollectionEmpty(cadesSignature.getSignatureTimestamps())) {
			signerInformation = super.extendSignerInformation(cmsSignedData, signerInformation, parameters);
			cadesSignature = newCAdESSignature(cmsSignedData, signerInformation, parameters.getDetachedContents());
		}
		// check if the resulted signature can be extended
		assertExtendSignaturePossible(cadesSignature);

		return signerInformation;
	}

	@Override
	protected CMSSignedData extendCMSSignedData(CMSSignedData cmsSignedData, SignerInformation signerInformation,
												CAdESSignatureParameters parameters) {
		CAdESSignature cadesSignature = newCAdESSignature(cmsSignedData, signerInformation, parameters.getDetachedContents());
		ValidationDataForInclusionBuilder validationDataForInclusionBuilder = getValidationDataForInclusionBuilder(cadesSignature);
		ValidationDataForInclusion validationDataForInclusion = validationDataForInclusionBuilder.build();
		return extendWithValidationData(cmsSignedData, validationDataForInclusion, parameters.getDetachedContents());
	}
	
	/**
	 * Returns a validation data for inclusion builder
	 * 
	 * @param cadesSignature {@link CAdESSignature} to get inclusion data for
	 * @return {@link ValidationDataForInclusionBuilder}
	 */
	protected ValidationDataForInclusionBuilder getValidationDataForInclusionBuilder(final CAdESSignature cadesSignature) {
		final ValidationContext validationContext = cadesSignature.getSignatureValidationContext(certificateVerifier);
		return new ValidationDataForInclusionBuilder(validationContext, cadesSignature.getCompleteCertificateSource());
	}

	/**
	 * Extends the {@code cmsSignedData} with the LT-level (validation data)
	 *
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param validationDataForInclusion {@link ValidationDataForInclusion} to include
	 * @param detachedContents a list of {@link DSSDocument} detached documents (only one is allowed)
	 * @return extended {@link CMSSignedData}
	 */
	protected CMSSignedData extendWithValidationData(CMSSignedData cmsSignedData,
													 ValidationDataForInclusion validationDataForInclusion,
													 List<DSSDocument> detachedContents) {
		final CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		cmsSignedData = cmsSignedDataBuilder.extendCMSSignedData(cmsSignedData, validationDataForInclusion, detachedContents);
		return cmsSignedData;
	}
	
	private void assertExtendSignaturePossible(CAdESSignature cadesSignature) throws DSSException {
		if (cadesSignature.areAllSelfSignedCertificates()) {
			throw new DSSException("Cannot extend the signature. The signature contains only self-signed certificate chains!");
		}
	}

}
