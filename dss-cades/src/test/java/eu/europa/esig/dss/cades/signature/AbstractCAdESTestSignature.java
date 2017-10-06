package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
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
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public abstract class AbstractCAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<CAdESSignatureParameters> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		checkSignedAttributesOrder(byteArray);

		checkGetOriginalDocument(byteArray);
	}

	private void checkGetOriginalDocument(byte[] byteArray) {
		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(new InMemoryDocument(byteArray));
		sdv.setCertificateVerifier(getCompleteCertificateVerifier());

		if (SignaturePackaging.DETACHED == getSignatureParameters().getSignaturePackaging()) {
			sdv.setDetachedContents(Arrays.asList(getDocumentToSign()));
		}

		List<AdvancedSignature> signatures = sdv.getSignatures();
		assertEquals(1, signatures.size());

		List<DSSDocument> originalDocuments = sdv.getOriginalDocuments(signatures.get(0).getId());
		assertEquals(1, originalDocuments.size());

		DSSDocument original = originalDocuments.get(0);
		String digest = original.getDigest(DigestAlgorithm.SHA384);
		String digest2 = getDocumentToSign().getDigest(DigestAlgorithm.SHA384);
		assertEquals(digest, digest2);
	}

	protected void checkSignedAttributesOrder(byte[] encoded) {
		ASN1InputStream asn1sInput = null;
		try {
			asn1sInput = new ASN1InputStream(encoded);
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
		} finally {
			Utils.closeQuietly(asn1sInput);
		}
	}

}
