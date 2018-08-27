package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertEquals;
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

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxObjectFactory;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public abstract class AbstractPAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<PAdESSignatureParameters> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {

		InMemoryDocument dssDocument = new InMemoryDocument(byteArray);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		PAdESSignature padesSig = (PAdESSignature) signatures.get(0);

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

}
