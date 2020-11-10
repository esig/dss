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
package eu.europa.esig.dss.pades.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.scope.PAdESSignatureScopeFinder;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DiagnosticDataBuilder;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

/**
 * Validation of PDF document.
 */
public class PDFDocumentValidator extends SignedDocumentValidator {

	private static final byte[] pdfPreamble = new byte[] { '%', 'P', 'D', 'F', '-' };

	private IPdfObjFactory pdfObjectFactory = new ServiceLoaderPdfObjFactory();

	private List<PdfRevision> documentRevisions;

	private String passwordProtection;

	PDFDocumentValidator() {
	}

	/**
	 * The default constructor for PDFDocumentValidator.
	 */
	public PDFDocumentValidator(final DSSDocument document) {
		super(new PAdESSignatureScopeFinder());
		this.document = document;
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return DSSUtils.compareFirstBytes(dssDocument, pdfPreamble);
	}

	/**
	 * Set the IPdfObjFactory. Allow to set the used implementation. Cannot be null.
	 * 
	 * @param pdfObjFactory the implementation to be used.
	 */
	public void setPdfObjFactory(IPdfObjFactory pdfObjFactory) {
		Objects.requireNonNull(pdfObjFactory, "PdfObjFactory is null");
		this.pdfObjectFactory = pdfObjFactory;
	}

	/**
	 * Specify the used password for the encrypted document
	 * 
	 * @param pwd the used password
	 */
	public void setPasswordProtection(String pwd) {
		this.passwordProtection = pwd;
	}

	@Override
	protected DiagnosticDataBuilder prepareDiagnosticDataBuilder(final ValidationContext validationContext) {

		List<AdvancedSignature> allSignatures = getAllSignatures();
		List<TimestampToken> detachedTimestamps = getDetachedTimestamps();
		List<PdfDssDict> dssDictionaries = getDssDictionaries();

		ListRevocationSource<CRL> listCRLSource = mergeCRLSources(allSignatures, detachedTimestamps, dssDictionaries);
		ListRevocationSource<OCSP> listOCSPSource = mergeOCSPSources(allSignatures, detachedTimestamps,
				dssDictionaries);
		ListCertificateSource listCertificateSource = mergeCertificateSource(allSignatures, detachedTimestamps,
				dssDictionaries);

		prepareCertificateVerifier(listCRLSource, listOCSPSource, listCertificateSource);

		prepareSignatureValidationContext(validationContext, allSignatures);
		prepareDetachedTimestampValidationContext(validationContext, detachedTimestamps);
		populateFromDssDictionaries(validationContext, dssDictionaries);

		if (!skipValidationContextExecution) {
			validateContext(validationContext);
		}

		return createDiagnosticDataBuilder(validationContext, allSignatures, listCRLSource, listOCSPSource);
	}

	@Override
	protected PAdESDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
		return new PAdESDiagnosticDataBuilder();
	}

	protected ListRevocationSource<CRL> mergeCRLSources(Collection<AdvancedSignature> allSignatures,
			Collection<TimestampToken> timestampTokens, Collection<PdfDssDict> dssDictionaries) {
		ListRevocationSource<CRL> listCRLSource = mergeCRLSources(allSignatures, timestampTokens);
		if (Utils.isCollectionNotEmpty(dssDictionaries)) {
			for (PdfDssDict dssDictionary : dssDictionaries) {
				listCRLSource.add(new PAdESCRLSource(dssDictionary));
			}
		}
		return listCRLSource;
	}

	protected ListRevocationSource<OCSP> mergeOCSPSources(Collection<AdvancedSignature> allSignatures,
			Collection<TimestampToken> timestampTokens, Collection<PdfDssDict> dssDictionaries) {
		ListRevocationSource<OCSP> listOCSPSource = mergeOCSPSources(allSignatures, timestampTokens);
		if (Utils.isCollectionNotEmpty(dssDictionaries)) {
			for (PdfDssDict dssDictionary : dssDictionaries) {
				listOCSPSource.add(new PAdESOCSPSource(dssDictionary));
			}
		}
		return listOCSPSource;
	}

	protected void populateFromDssDictionaries(final ValidationContext validationContext, List<PdfDssDict> dssDicts) {
		for (PdfDssDict dssDict : dssDicts) {
			for (CertificateToken certificateToken : dssDict.getCERTs().values()) {
				validationContext.addCertificateTokenForVerification(certificateToken);
			}
		}
	}

	protected ListCertificateSource mergeCertificateSource(final Collection<AdvancedSignature> allSignatureList,
			Collection<TimestampToken> detachedTimestamps, List<PdfDssDict> dssDictionaries) {
		ListCertificateSource allCertificatesSource = mergeCertificateSource(allSignatureList, detachedTimestamps);
		// TODO dssDictionaries
		return allCertificatesSource;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		final List<AdvancedSignature> signatures = new ArrayList<>();

		for (PdfRevision pdfRevision : getRevisions()) {
			if (pdfRevision instanceof PdfSignatureRevision) {
				PdfSignatureRevision pdfSignatureRevision = (PdfSignatureRevision) pdfRevision;
				try {
					final PAdESSignature padesSignature = new PAdESSignature(pdfSignatureRevision, documentRevisions);
					padesSignature.setSignatureFilename(document.getName());
					padesSignature.setSigningCertificateSource(signingCertificateSource);
					padesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
					signatures.add(padesSignature);

				} catch (Exception e) {
					throw new DSSException(
							String.format("Unable to collect a signature. Reason : [%s]", e.getMessage()), e);
				}

			}
		}
		Collections.reverse(signatures);
		return signatures;
	}

	@Override
	public List<TimestampToken> getDetachedTimestamps() {
		final List<TimestampToken> timestamps = new ArrayList<>();

		for (PdfRevision pdfRevision : getRevisions()) {
			if (pdfRevision instanceof PdfDocTimestampRevision) {
				PdfDocTimestampRevision pdfDocTimestampRevision = (PdfDocTimestampRevision) pdfRevision;
				try {
					TimestampToken timestampToken = new PdfTimestampToken(pdfDocTimestampRevision,
							TimestampType.CONTENT_TIMESTAMP);
					timestampToken.setFileName(document.getName());
					timestampToken.matchData(new InMemoryDocument(pdfDocTimestampRevision.getRevisionCoveredBytes()));

					PAdESSignatureScopeFinder signatureScopeFinder = new PAdESSignatureScopeFinder();
					signatureScopeFinder.setDefaultDigestAlgorithm(getDefaultDigestAlgorithm());
					timestampToken.setTimestampScopes(
							Arrays.asList(signatureScopeFinder.findSignatureScope(pdfDocTimestampRevision)));

					timestamps.add(timestampToken);

				} catch (Exception e) {
					throw new DSSException(
							String.format("Unable to collect a timestamp. Reason : [%s]", e.getMessage()), e);
				}

			}
		}
		Collections.reverse(timestamps);
		return timestamps;
	}

	/**
	 * Returns a list of found DSS Dictionaries across different revisions
	 * 
	 * @return list of {@link PdfDssDict}s
	 */
	public List<PdfDssDict> getDssDictionaries() {
		List<PdfDssDict> docDssRevisions = new ArrayList<>();

		for (PdfRevision pdfRevision : getRevisions()) {
			if (pdfRevision instanceof PdfDocDssRevision) {
				PdfDocDssRevision dssRevision = (PdfDocDssRevision) pdfRevision;
				docDssRevisions.add(dssRevision.getDssDictionary());
			}
		}
		Collections.reverse(docDssRevisions);
		return docDssRevisions;
	}

	protected List<PdfRevision> getRevisions() {
		if (documentRevisions == null) {
			PDFSignatureService pdfSignatureService = pdfObjectFactory.newPAdESSignatureService();
			documentRevisions = pdfSignatureService.getRevisions(document, passwordProtection);
		}
		return documentRevisions;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) {
		Objects.requireNonNull(signatureId, "Signature Id cannot be null");
		List<AdvancedSignature> signatures = getSignatures();
		for (AdvancedSignature signature : signatures) {
			if (signature.getId().equals(signatureId)) {
				return getOriginalDocuments(signature);
			}
		}
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		PAdESSignature padesSignature = (PAdESSignature) advancedSignature;
		List<DSSDocument> result = new ArrayList<>();
		InMemoryDocument originalPDF = PAdESUtils.getOriginalPDF(padesSignature);
		if (originalPDF != null) {
			result.add(originalPDF);
		}
		return result;
	}

}
