package eu.europa.esig.dss.cades;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Basic support of ETSI EN 319 122-1 V1.1.1 chapter 5.2.6.1
 * 
 * <pre>
 * 	CertifiedAttributesV2 ::= SEQUENCE OF CHOICE {
 * 		attributeCertificate [0] AttributeCertificate,
 * 		otherAttributeCertificate [1] OtherAttributeCertificate
 *	}
 * </pre>
 * 
 * Note : OtherAttributeCertificate is not supported.
 * Quote ETSI : The definition of specific otherAttributeCertificates is outside of the scope of the present document.
 */
public class CertifiedAttributesV2 extends ASN1Object {

	private static final Logger LOG = LoggerFactory.getLogger(CertifiedAttributesV2.class);

	private Object[] values;

	public static CertifiedAttributesV2 getInstance(Object o) {
		if (o instanceof CertifiedAttributesV2) {
			return (CertifiedAttributesV2) o;
		} else if (o != null) {
			return new CertifiedAttributesV2(ASN1Sequence.getInstance(o));
		}

		return null;
	}

	@SuppressWarnings("rawtypes")
	private CertifiedAttributesV2(ASN1Sequence seq) {
		int index = 0;
		values = new Object[seq.size()];

		for (Enumeration e = seq.getObjects(); e.hasMoreElements();) {
			ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(e.nextElement());

			if (taggedObject.getTagNo() == 0) {
				values[index] = AttributeCertificate.getInstance(ASN1Sequence.getInstance(taggedObject, true));
			} else if (taggedObject.getTagNo() == 1) {
				LOG.info("OtherAttributeCertificate detected");
			} else {
				throw new IllegalArgumentException("illegal tag: " + taggedObject.getTagNo());
			}
			index++;
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		for (int i = 0; i != values.length; i++) {
			if (values[i] instanceof AttributeCertificate) {
				v.add(new DERTaggedObject(0, (AttributeCertificate) values[i]));
			} else {
				LOG.warn("Unsupported type " + values[i]);
			}
		}
		return new DERSequence(v);
	}

}
