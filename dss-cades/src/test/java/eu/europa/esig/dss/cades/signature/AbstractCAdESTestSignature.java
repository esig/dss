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
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractCAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		checkSignedAttributesOrder(byteArray);
		checkSignaturePackaging(byteArray);
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	protected void checkSignedAttributesOrder(byte[] encoded) {
		try (ASN1InputStream asn1sInput = new ASN1InputStream(encoded)) {
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

			SignedData signedData = SignedData.getInstance(DERTaggedObject.getInstance(asn1Seq.getObjectAt(1)).getBaseObject());

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

	protected void checkSignaturePackaging(byte[] byteArray) {
		try {
			CMSSignedData cmsSignedData = new CMSSignedData(byteArray);
			assertEquals(SignaturePackaging.DETACHED.equals(getSignatureParameters().getSignaturePackaging()),
					cmsSignedData.isDetachedSignature());
			assertEquals(SignaturePackaging.DETACHED.equals(getSignatureParameters().getSignaturePackaging()),
					cmsSignedData.getSignedContent() == null);

		} catch (CMSException e) {
			fail(e);
		}
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
			if (Utils.isTrue(signerInfo.isCurrent())) {
				++verifiedNumber;
			}
		}
		assertEquals(1, verifiedNumber);
		
		assertEquals(1, signatureInformationStore.size());
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureValue());
		}
	}
	
	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
			SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());
			
			SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
			assertNotNull(signatureIdentifier);
			
			assertNotNull(signatureIdentifier.getSignatureValue());
			assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
		}
	}

	@Override
	protected void checkMimeType(DSSDocument signedDocument) {
		super.checkMimeType(signedDocument);
		checkFileExtension(signedDocument);
	}

	protected void checkFileExtension(DSSDocument document) {
		String documentName = document.getName();
		assertNotNull(documentName);

		String extension = Utils.getFileNameExtension(documentName);
		assertNotNull(extension);

		if (SignaturePackaging.DETACHED.equals(getSignatureParameters().getSignaturePackaging())) {
			assertEquals("p7s", extension);
		} else {
			assertEquals("p7m", extension);
		}
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (!signatureWrapper.isCounterSignature() && Utils.isStringEmpty(signatureWrapper.getContentHints())) {
				assertNotNull(signatureWrapper.getMimeType());
			} else {
				assertNull(signatureWrapper.getMimeType());
			}
		}
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeTypeEnum.PKCS7;
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.CAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.CAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.CAdES_BASELINE_T.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		return SignatureLevel.CAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
	}

}
