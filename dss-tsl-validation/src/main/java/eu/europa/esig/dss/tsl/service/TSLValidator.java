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
package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.util.List;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.tsl.TSLValidationResult;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import eu.europa.esig.dss.xades.validation.XmlRootSignatureScope;

/**
 * This class allows to validate TSL or LOTL. It can be executed as a Callable.
 */
public class TSLValidator implements Callable<TSLValidationResult> {

	private static final Logger LOG = LoggerFactory.getLogger(TSLValidator.class);

	private File file;
	private String countryCode;
	private List<CertificateToken> potentialSigners;

	/**
	 * Constructor used to instantiate a validator for a TSL
	 *
	 * @param file
	 *            the file to validate (a TSL file (not LOTL)
	 * @param countryCode
	 *            the country code
	 * @param potentialSigners
	 *            the list of certificates allowed to sign this TSL
	 */
	public TSLValidator(File file, String countryCode, List<CertificateToken> potentialSigners) {
		this.file = file;
		this.countryCode = countryCode;
		this.potentialSigners = potentialSigners;
	}

	@Override
	public TSLValidationResult call() throws Exception {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier(true);
		certificateVerifier.setTrustedCertSource(buildTrustedCertificateSource(potentialSigners));

		DSSDocument dssDocument = new FileDocument(file);
		XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(dssDocument);
		xmlDocumentValidator.setCertificateVerifier(certificateVerifier);
		xmlDocumentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES); // Timestamps,... are ignored
		// To increase the security: the default {@code XPathQueryHolder} is
		// used.
		List<XPathQueryHolder> xPathQueryHolders = xmlDocumentValidator.getXPathQueryHolder();
		xPathQueryHolders.clear();
		xPathQueryHolders.add(new XPathQueryHolder());

		Reports reports = xmlDocumentValidator.validateDocument(TSLValidator.class.getResourceAsStream("/tsl-constraint.xml"));

		// TODO improve with DSS-1487
		boolean acceptableScope = false;
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
		if (Utils.collectionSize(signatureScopes) == 1) {
			XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
			acceptableScope = XmlRootSignatureScope.class.getSimpleName().equals(xmlSignatureScope.getScope());
		}

		SimpleReport simpleReport = reports.getSimpleReport();
		Indication indication = simpleReport.getIndication(simpleReport.getFirstSignatureId());
		boolean isValid = acceptableScope && Indication.TOTAL_PASSED.equals(indication);

		TSLValidationResult result = new TSLValidationResult();
		result.setCountryCode(countryCode);
		if (acceptableScope) {
			result.setIndication(indication);
		} else {
			result.setIndication(Indication.TOTAL_FAILED);
		}
		result.setSubIndication(simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		if (!isValid) {
			LOG.info("The TSL signature is not valid : \n{}", reports.getXmlSimpleReport());
		}

		return result;
	}

	private CommonTrustedCertificateSource buildTrustedCertificateSource(List<CertificateToken> potentialSigners) {
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		if (Utils.isCollectionNotEmpty(potentialSigners)) {
			for (CertificateToken potentialSigner : potentialSigners) {
				commonTrustedCertificateSource.addCertificate(potentialSigner);
			}
		}
		return commonTrustedCertificateSource;
	}

}
