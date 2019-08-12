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
package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SAContactInfoType;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SAFilterType;
import eu.europa.esig.validationreport.jaxb.SANameType;
import eu.europa.esig.validationreport.jaxb.SAReasonType;
import eu.europa.esig.validationreport.jaxb.SASignatureProductionPlaceType;
import eu.europa.esig.validationreport.jaxb.SASubFilterType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;

public abstract class AbstractPAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<PAdESSignatureParameters> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {

		InMemoryDocument dssDocument = new InMemoryDocument(byteArray);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		PAdESSignature padesSig = (PAdESSignature) signatures.get(0);

		PdfSignatureInfo pdfSignatureInfo = padesSig.getPdfSignatureInfo();
		assertEquals(getSignatureParameters().getSignatureFilter(), pdfSignatureInfo.getFilter());
		assertEquals(getSignatureParameters().getSignatureSubFilter(), pdfSignatureInfo.getSubFilter());
		assertEquals(getSignatureParameters().getReason(), pdfSignatureInfo.getReason());
		assertEquals(getSignatureParameters().getContactInfo(), pdfSignatureInfo.getContactInfo());
		assertEquals(getSignatureParameters().getLocation(), pdfSignatureInfo.getLocation());

		if (padesSig.isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_LT)) {
			assertNotNull(pdfSignatureInfo.getDssDictionary());
		}

		assertNotNull(pdfSignatureInfo.getSigningDate());
		assertNull(pdfSignatureInfo.getCades().getSigningTime());

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		List<String> originalSignatureFields = service.getAvailableSignatureFields(getDocumentToSign());
		int originalSignatureFieldsNumber = originalSignatureFields.size();

		List<String> availableSignatureFields = service.getAvailableSignatureFields(dssDocument);
		int availableSignatureFieldsNumber = availableSignatureFields.size();

		if ((originalSignatureFieldsNumber > 0)) {
			if (originalSignatureFields.contains(getSignatureParameters().getSignatureFieldId())) {
				assertEquals(availableSignatureFieldsNumber, originalSignatureFieldsNumber - 1);
			} else {
				assertEquals(availableSignatureFieldsNumber, originalSignatureFieldsNumber);
			}
		} else {
			assertEquals(0, availableSignatureFieldsNumber);
		}

		checkSignedAttributesOrder(padesSig);
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	protected void checkSignedAttributesOrder(PAdESSignature padesSig) {
		try (ASN1InputStream asn1sInput = new ASN1InputStream(padesSig.getCAdESSignature().getCmsSignedData().getEncoded())) {
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

			SignedData signedData = SignedData.getInstance(DERTaggedObject.getInstance(asn1Seq.getObjectAt(1)).getObject());

			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			SignerInfo signedInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));

			ASN1Set authenticatedAttributeSet = signedInfo.getAuthenticatedAttributes();

			int previousSize = 0;
			for (int i = 0; i < authenticatedAttributeSet.size(); i++) {
				Attribute attribute = Attribute.getInstance(authenticatedAttributeSet.getObjectAt(i));
				ASN1ObjectIdentifier attrTypeOid = attribute.getAttrType();
				int size = attrTypeOid.getEncoded().length + attribute.getEncoded().length;

				assertTrue(size >= previousSize);
				previousSize = size;
			}
		} catch (Exception e) {
			fail(e.getMessage());
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
	protected void validateETSISASignatureProductionPlaceType(SASignatureProductionPlaceType productionPlace) {
		List<String> addressString = productionPlace.getAddressString();
		String signerLocation = getSignatureParameters().getLocation();
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
		String subFilter = getSignatureParameters().getSignatureSubFilter();
		assertEquals(subFilter, subFilterType.getSubFilterElement());
	}

	@Override
	protected void validateETSIFilter(SAFilterType filterType) {
		String filter = getSignatureParameters().getSignatureFilter();
		assertEquals(filter, filterType.getFilter());
	}

	@Override
	protected void validateETSIContactInfo(SAContactInfoType contactTypeInfo) {
		String contactInfo = getSignatureParameters().getContactInfo();
		assertEquals(contactInfo, contactTypeInfo.getContactInfoElement());
	}

	@Override
	protected void validateETSISAName(SANameType nameType) {
		String signatureName = getSignatureParameters().getSignatureName();
		// if null, DSS generates the signature name
		if (signatureName != null) {
			assertEquals(signatureName, nameType.getNameElement());
		}
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
	protected void checkNoDuplicateCompleteCertificates(DiagnosticData diagnosticData) {
		// "Duplicate"
	}

	@Override
	protected void checkNoDuplicateCompleteRevocationData(DiagnosticData diagnosticData) {
		// "Duplicate"
	}
}
