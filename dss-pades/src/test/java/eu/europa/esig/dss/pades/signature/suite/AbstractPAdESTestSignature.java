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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SAContactInfoType;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SAFilterType;
import eu.europa.esig.validationreport.jaxb.SANameType;
import eu.europa.esig.validationreport.jaxb.SAReasonType;
import eu.europa.esig.validationreport.jaxb.SASignatureProductionPlaceType;
import eu.europa.esig.validationreport.jaxb.SASubFilterType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractPAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {

		InMemoryDocument dssDocument = new InMemoryDocument(byteArray);

		SignedDocumentValidator validator = getValidator(dssDocument);
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));

		PAdESSignature padesSig = (PAdESSignature) signatures.get(0);

		PdfSignatureDictionary pdfSigDict = padesSig.getPdfSignatureDictionary();
		assertEquals(getSignatureParameters().getSignerName(), pdfSigDict.getSignerName());
		assertEquals(getSignatureParameters().getFilter(), pdfSigDict.getFilter());
		assertEquals(getSignatureParameters().getSubFilter(), pdfSigDict.getSubFilter());
		assertEquals(getSignatureParameters().getReason(), pdfSigDict.getReason());
		assertEquals(getSignatureParameters().getContactInfo(), pdfSigDict.getContactInfo());
		assertEquals(getSignatureParameters().getLocation(), pdfSigDict.getLocation());
		
		PdfSignatureRevision pdfSignatureRevision = padesSig.getPdfRevision();

		SignatureLevel currentLevel = padesSig.getDataFoundUpToLevel();
		if (SignatureLevel.PAdES_BASELINE_LT.equals(currentLevel) || SignatureLevel.PAdES_BASELINE_LTA.equals(currentLevel)) {
			assertNotNull(pdfSignatureRevision.getDssDictionary());
		}

		assertNotNull(pdfSignatureRevision.getSigningDate());

		PAdESService service = new PAdESService(getOfflineCertificateVerifier());
		List<String> originalSignatureFields = service.getAvailableSignatureFields(getDocumentToSign(), getPasswordProtection());
		int originalSignatureFieldsNumber = originalSignatureFields.size();

		List<String> availableSignatureFields = service.getAvailableSignatureFields(dssDocument, getPasswordProtection());
		int availableSignatureFieldsNumber = availableSignatureFields.size();

		if ((originalSignatureFieldsNumber > 0)) {
			if (originalSignatureFields.contains(getSignatureParameters().getImageParameters().getFieldParameters().getFieldId())) {
				assertEquals(availableSignatureFieldsNumber, originalSignatureFieldsNumber - 1);
			} else {
				assertEquals(availableSignatureFieldsNumber, originalSignatureFieldsNumber);
			}
		} else {
			assertEquals(0, availableSignatureFieldsNumber);
		}

		checkSignedAttributesOrder(padesSig);
	}
	
	protected String getPasswordProtection() {
		return getSignatureParameters().getPasswordProtection();
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}
	
	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		// verify PDFInfo
		assertEquals(getSignatureParameters().getSignerName(), signature.getSignerName());
		assertEquals(getSignatureParameters().getFilter(), signature.getFilter());
		assertEquals(getSignatureParameters().getSubFilter(), signature.getSubFilter());
		assertEquals(getSignatureParameters().getReason(), signature.getReason());
		assertEquals(getSignatureParameters().getContactInfo(), signature.getContactInfo());
		assertEquals(getSignatureParameters().getLocation(), signature.getLocation());
	}
	
	@Override
	protected void checkSignatureProductionPlace(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureWrapper.isSignatureProductionPlacePresent()); // see PdfSignatureDictionary.location
	}

	@Override
	protected void checkSignatureInformationStore(DiagnosticData diagnosticData) {
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			checkSignatureInformationStore(signature.getSignatureInformationStore());
		}
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			checkSignatureInformationStore(timestamp.getSignatureInformationStore());
		}
	}
	
	private void checkSignatureInformationStore(List<XmlSignerInfo> signatureInformationStore) {
		assertNotNull(signatureInformationStore);
		int verifiedNumber = 0;
		for (XmlSignerInfo signerInfo : signatureInformationStore) {
			if (signerInfo.isCurrent()) {
				++verifiedNumber;
			}
		}
		assertEquals(1, verifiedNumber);
		
		assertEquals(1, signatureInformationStore.size());
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);

		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			assertNotNull(signature.getPDFRevision());
			
			assertTrue(Utils.isCollectionNotEmpty(signature.getSignatureFieldNames()));
			
			assertNotNull(signature.getSignatureDictionaryType());
			assertNotNull(signature.getFilter());
			assertNotNull(signature.getSubFilter());
			assertNotNull(signature.getSignatureByteRange());
			
			assertFalse(signature.arePdfModificationsDetected());
			assertTrue(Utils.isCollectionEmpty(signature.getPdfUndefinedChanges()));
		}
		
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (TimestampType.DOCUMENT_TIMESTAMP.equals(timestamp.getType())) {
				assertNotNull(timestamp.getPDFRevision());
				
				assertTrue(Utils.isCollectionNotEmpty(timestamp.getSignatureFieldNames()));
				
				assertNotNull(timestamp.getSignatureDictionaryType());
				assertNotNull(timestamp.getFilter());
				assertNotNull(timestamp.getSubFilter());
				assertNotNull(timestamp.getSignatureByteRange());		
				
				assertFalse(timestamp.arePdfModificationsDetected());
				assertTrue(Utils.isCollectionEmpty(timestamp.getPdfUndefinedChanges()));
			}
		}
	}

	protected void checkSignedAttributesOrder(PAdESSignature padesSig) {
		try (ASN1InputStream asn1sInput = new ASN1InputStream(padesSig.getCmsSignedData().getEncoded())) {
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

			SignedData signedData = SignedData.getInstance(ASN1TaggedObject.getInstance(asn1Seq.getObjectAt(1)).getBaseObject());

			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			SignerInfo signedInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));

			ASN1Set authenticatedAttributeSet = signedInfo.getAuthenticatedAttributes();

			int previousSize = 0;
			for (int i = 0; i < authenticatedAttributeSet.size(); i++) {
				Attribute attribute = Attribute.getInstance(authenticatedAttributeSet.getObjectAt(i));
				ASN1ObjectIdentifier attrTypeOid = attribute.getAttrType();
				ASN1Set attrValues = attribute.getAttrValues();
				int size = attrTypeOid.getEncoded().length + attrValues.getEncoded().length;

				assertTrue(size >= previousSize);
				previousSize = size;
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNull(signatureWrapper.getMimeType());
		}
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.PDF;
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.PAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.PAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.PAdES_BASELINE_T.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		return SignatureLevel.PAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertNotNull(signatureScopes);
		assertEquals(1, signatureScopes.size());
		XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		if (SignatureLevel.PAdES_BASELINE_B == signatureLevel || SignatureLevel.PAdES_BASELINE_T == signatureLevel) {
			assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
		} else {
			assertEquals(SignatureScopeType.PARTIAL, xmlSignatureScope.getScope());
		}
	}

	@Override
	protected void validateETSISASignatureProductionPlaceType(SASignatureProductionPlaceType productionPlace, SerializableSignatureParameters parameters) {
		PAdESSignatureParameters padesSignatureParameters = (PAdESSignatureParameters) parameters;
		String signerLocation = padesSignatureParameters.getLocation();
		List<String> addressString = productionPlace.getAddressString();
		if (signerLocation != null) {
			assertTrue(addressString.contains(signerLocation));
		} else {
			fail("Not defined location");
		}
	}

	@Override
	protected void validateETSISAReasonType(SAReasonType reasonType) {
		String reason = getSignatureParameters().getReason();
		assertEquals(reason, reasonType.getReasonElement());
	}

	@Override
	protected void validateETSISubFilter(SASubFilterType subFilterType) {
		String subFilter = getSignatureParameters().getSubFilter();
		assertEquals(subFilter, subFilterType.getSubFilterElement());
	}

	@Override
	protected void validateETSIFilter(SAFilterType filterType) {
		String filter = getSignatureParameters().getFilter();
		assertEquals(filter, filterType.getFilter());
	}

	@Override
	protected void validateETSIContactInfo(SAContactInfoType contactTypeInfo) {
		String contactInfo = getSignatureParameters().getContactInfo();
		assertEquals(contactInfo, contactTypeInfo.getContactInfoElement());
	}

	@Override
	protected void validateETSISAName(SANameType nameType) {
		String signerName = getSignatureParameters().getSignerName();
		assertEquals(signerName, nameType.getNameElement());
	}

	@Override
	protected void validateETSIDSSType(SADSSType dss) {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		if (SignatureLevel.PAdES_BASELINE_LT.equals(signatureLevel) || SignatureLevel.PAdES_BASELINE_LTA.equals(signatureLevel)) {
			assertNotNull(dss);
		} else {
			assertNull(dss);
		}
	}

	@Override
	protected void validateETSIVRIType(SAVRIType vri) {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		if (SignatureLevel.PAdES_BASELINE_LT.equals(signatureLevel) || SignatureLevel.PAdES_BASELINE_LTA.equals(signatureLevel)) {
			assertNotNull(vri);
		} else {
			assertNull(vri);
		}
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature.getSignatureValue());
	}

	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		
		if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
			for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
				SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());
				
				SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
				assertNotNull(signatureIdentifier);
				
				assertNotNull(signatureIdentifier.getSignatureValue());
                assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
			}
		}
	}

	@Override
	protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
		// "Duplicate"
	}

	@Override
	protected void checkNoDuplicateCompleteRevocationData(DiagnosticData diagnosticData) {
		// "Duplicate"
	}
}
