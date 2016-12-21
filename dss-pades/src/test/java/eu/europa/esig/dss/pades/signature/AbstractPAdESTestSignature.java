package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.signature.AbstractTestDocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public abstract class AbstractPAdESTestSignature extends AbstractTestDocumentSignatureService {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		checkSignedAttributesOrder(byteArray);
	}

	protected void checkSignedAttributesOrder(byte[] encoded) {

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(encoded));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		try {
			PAdESSignature padesSig = (PAdESSignature) signatures.get(0);
			byte[] encodedCMS = padesSig.getCAdESSignature().getCmsSignedData().getEncoded();

			ASN1InputStream asn1sInput = new ASN1InputStream(encodedCMS);
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

}
