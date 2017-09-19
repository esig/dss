package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractCAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<CAdESSignatureParameters> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		checkSignedAttributesOrder(byteArray);
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
