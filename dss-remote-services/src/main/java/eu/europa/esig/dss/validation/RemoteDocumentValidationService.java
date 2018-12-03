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
package eu.europa.esig.dss.validation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteConverter;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;

public class RemoteDocumentValidationService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteDocumentValidationService.class);

	private CertificateVerifier verifier;

	public void setVerifier(CertificateVerifier verifier) {
		this.verifier = verifier;
	}

	public ReportsDTO validateDocument(RemoteDocument signedFile, List<RemoteDocument> originalFiles, RemoteDocument policy) {
		LOG.info("ValidateDocument in process...");
		DocumentValidator validator = initValidator(signedFile, originalFiles);

		Reports reports = null;
		if (policy == null) {
			reports = validator.validateDocument();
		} else {
			try (ByteArrayInputStream bais = new ByteArrayInputStream(policy.getBytes())) {
				reports = validator.validateDocument(bais);
			} catch (IOException e) {
				throw new DSSException(e);
			}
		}

		ReportsDTO reportsDTO = new ReportsDTO(reports.getDiagnosticDataJaxb(), reports.getSimpleReportJaxb(), reports.getDetailedReportJaxb());
		LOG.info("ValidateDocument is finished");
		return reportsDTO;
	}

	public List<RemoteDocument> getOriginalDocuments(RemoteDocument signedFile, List<RemoteDocument> originalFiles, String signatureId) {
		LOG.info("GetOriginalDocuments in process...");
		DocumentValidator validator = initValidator(signedFile, originalFiles);

		if (signatureId == null) {
			List<AdvancedSignature> signatures = validator.getSignatures();
			if (signatures.size() > 0) {
				LOG.debug("SignatureId is not defined, the first signature is used");
				signatureId = signatures.get(0).getId();
			}
		}

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatureId);
		List<RemoteDocument> remoteDocuments = RemoteConverter.toRemoteDocuments(originalDocuments);
		LOG.info("GetOriginalDocuments is finished");
		return remoteDocuments;
	}

	private DocumentValidator initValidator(RemoteDocument signedFile, List<RemoteDocument> originalFiles) {
		DSSDocument signedDocument = RemoteConverter.toDSSDocument(signedFile);
		SignedDocumentValidator signedDocValidator = SignedDocumentValidator.fromDocument(signedDocument);
		signedDocValidator.setCertificateVerifier(verifier);
		if (Utils.isCollectionNotEmpty(originalFiles)) {
			signedDocValidator.setDetachedContents(RemoteConverter.toDSSDocuments(originalFiles));
		}
		return signedDocValidator;
	}

}
