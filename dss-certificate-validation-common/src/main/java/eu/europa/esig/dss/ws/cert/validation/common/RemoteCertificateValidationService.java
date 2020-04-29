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
package eu.europa.esig.dss.ws.cert.validation.common;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateReportsDTO;
import eu.europa.esig.dss.ws.cert.validation.dto.CertificateToValidateDTO;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

public class RemoteCertificateValidationService {

	private static final Logger LOG = LoggerFactory.getLogger(RemoteCertificateValidationService.class);

	private CertificateVerifier verifier;

	public void setVerifier(CertificateVerifier verifier) {
		this.verifier = verifier;
	}
	
	public CertificateReportsDTO validateCertificate(CertificateToValidateDTO certificateToValidate) {
		LOG.info("ValidateCertificate in process...");
		CertificateValidator validator = initValidator(certificateToValidate);
		
		CertificateReports reports = validator.validate();
		CertificateReportsDTO certificateReportsDTO = new CertificateReportsDTO(reports.getDiagnosticDataJaxb(), 
				reports.getSimpleReportJaxb(), reports.getDetailedReportJaxb());
		LOG.info("ValidateCertificate is finished");
		
		return certificateReportsDTO;
	}
	
	private CertificateValidator initValidator(CertificateToValidateDTO certificateToValidate) {
		CertificateSource adjunctCertSource = getAdjunctCertificateSource(certificateToValidate.getCertificateChain());
		
		CertificateVerifier usedCertificateVerifier = null;
		if (adjunctCertSource == null) {
			usedCertificateVerifier = verifier;
		} else {
			usedCertificateVerifier = new CertificateVerifierBuilder(verifier).buildCompleteCopy();
			usedCertificateVerifier.setAdjunctCertSources(adjunctCertSource);
		}

		CertificateToken certificateToken = RemoteCertificateConverter.toCertificateToken(certificateToValidate.getCertificate());
		CertificateValidator certificateValidator = CertificateValidator.fromCertificate(certificateToken);
		certificateValidator.setCertificateVerifier(usedCertificateVerifier);
		if (certificateToValidate.getValidationTime() != null) {
			certificateValidator.setValidationTime(certificateToValidate.getValidationTime());
		}
		if (certificateToValidate.getTokenExtractionStategy() != null) {
			certificateValidator.setTokenExtractionStategy(certificateToValidate.getTokenExtractionStategy());
		}
		return certificateValidator;
	}

	private CertificateSource getAdjunctCertificateSource(List<RemoteCertificate> certificateChain) {
		CertificateSource adjunctCertSource = null;
		if (Utils.isCollectionNotEmpty(certificateChain)) {
			adjunctCertSource = new CommonCertificateSource();
			for (RemoteCertificate certificateInChain : certificateChain) {
				CertificateToken certificateChainItem = RemoteCertificateConverter.toCertificateToken(certificateInChain);
				if (certificateChainItem != null) {
					adjunctCertSource.addCertificate(certificateChainItem);
				}
			}
		}
		return adjunctCertSource;
	}

}
