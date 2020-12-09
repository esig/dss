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
package eu.europa.esig.dss.ws.validation.common;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.util.List;

/**
 * The remote validation service
 */
public class RemoteDocumentValidationService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteDocumentValidationService.class);

	/** The certificate verifier to use */
	private CertificateVerifier verifier;

	/**
	 * Sets the certificate verifier
	 *
	 * @param verifier {@link CertificateVerifier}
	 */
	public void setVerifier(CertificateVerifier verifier) {
		this.verifier = verifier;
	}

	/**
	 * Validates the document
	 *
	 * @param dataToValidate {@link DataToValidateDTO} the request
	 * @return {@link WSReportsDTO} response
	 */
	public WSReportsDTO validateDocument(DataToValidateDTO dataToValidate) {
		LOG.info("ValidateDocument in process...");
		SignedDocumentValidator validator = initValidator(dataToValidate);

		Reports reports = null;
		RemoteDocument policy = dataToValidate.getPolicy();
		if (policy == null) {
			reports = validator.validateDocument();
		} else {
			reports = validator.validateDocument(getValidationPolicy(policy));
		}

		WSReportsDTO reportsDTO = new WSReportsDTO(reports.getDiagnosticDataJaxb(), reports.getSimpleReportJaxb(), 
				reports.getDetailedReportJaxb(), reports.getEtsiValidationReportJaxb());
		LOG.info("ValidateDocument is finished");
		return reportsDTO;
	}

	/**
	 * Gets the original documents
	 *
	 * @param dataToValidate {@link DataToValidateDTO} request
	 * @return a list of {@link RemoteDocument}s
	 */
	public List<RemoteDocument> getOriginalDocuments(DataToValidateDTO dataToValidate) {
		LOG.info("GetOriginalDocuments in process...");
		SignedDocumentValidator validator = initValidator(dataToValidate);

		String signatureId = dataToValidate.getSignatureId();
		if (signatureId == null) {
			List<AdvancedSignature> signatures = validator.getSignatures();
			if (signatures.size() > 0) {
				LOG.debug("SignatureId is not defined, the first signature is used");
				signatureId = signatures.get(0).getId();
			}
		}

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatureId);
		List<RemoteDocument> remoteDocuments = RemoteDocumentConverter.toRemoteDocuments(originalDocuments);
		LOG.info("GetOriginalDocuments is finished");
		return remoteDocuments;
	}

	private ValidationPolicy getValidationPolicy(RemoteDocument policy) {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(policy.getBytes())) {
			return ValidationPolicyFacade.newFacade().getValidationPolicy(bais);
		} catch (Exception e) {
			throw new DSSException("Unable to load the validation policy", e);
		}
	}

	private SignedDocumentValidator initValidator(DataToValidateDTO dataToValidate) {
		DSSDocument signedDocument = RemoteDocumentConverter.toDSSDocument(dataToValidate.getSignedDocument());
		SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);
		if (Utils.isCollectionNotEmpty(dataToValidate.getOriginalDocuments())) {
			signedDocValidator.setDetachedContents(RemoteDocumentConverter.toDSSDocuments(dataToValidate.getOriginalDocuments()));
		}
		signedDocValidator.setCertificateVerifier(verifier);
		// If null, uses default (NONE)
		if (dataToValidate.getTokenExtractionStrategy() != null) {
			signedDocValidator.setTokenExtractionStategy(dataToValidate.getTokenExtractionStrategy());
		}
		return signedDocValidator;
	}

}
