package eu.europa.esig.dss.validation;

import static eu.europa.esig.dss.OID.attributeCertificateRefsOid;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.CertificateRef;
import eu.europa.esig.dss.CertificateRefLocation;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignatureCertificateSource;

@SuppressWarnings("serial")
public abstract class CMSCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(CMSCertificateSource.class);

	protected transient final AttributeTable unsignedAttributes;

	protected CMSCertificateSource(final AttributeTable unsignedAttributes, CertificatePool certPool) {
		super(certPool);
		this.unsignedAttributes = unsignedAttributes;
	}

	@Override
	public List<CertificateToken> getCertificateValues() {
		return getCertificateFromUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certValues);
	}

	@Override
	public List<CertificateRef> getCompleteCertificateRefs() {
		return getCertificateRefsFromUnsignedAttribute(id_aa_ets_certificateRefs, CertificateRefLocation.COMPLETE_CERTIFICATE_REFS);
	}

	@Override
	public List<CertificateRef> getAttributeCertificateRefs() {
		return getCertificateRefsFromUnsignedAttribute(attributeCertificateRefsOid, CertificateRefLocation.ATTRIBUTE_CERTIFICATE_REFS);
	}

	private List<CertificateToken> getCertificateFromUnsignedAttribute(ASN1ObjectIdentifier attributeOid) {
		final List<CertificateToken> certs = new ArrayList<CertificateToken>();
		if (unsignedAttributes != null) {
			Attribute attribute = unsignedAttributes.get(attributeOid);
			if (attribute != null) {
				final ASN1Sequence seq = (ASN1Sequence) attribute.getAttrValues().getObjectAt(0);
				for (int ii = 0; ii < seq.size(); ii++) {
					try {
						final Certificate cs = Certificate.getInstance(seq.getObjectAt(ii));
						final CertificateToken certToken = addCertificate(DSSUtils.loadCertificate(cs.getEncoded()));
						if (!certs.contains(certToken)) {
							certs.add(certToken);
						}
					} catch (Exception e) {
						LOG.warn("Unable to parse encapsulated certificate : {}", e.getMessage());
					}
				}
			}
		}
		return certs;
	}

	private List<CertificateRef> getCertificateRefsFromUnsignedAttribute(ASN1ObjectIdentifier attributeOid, CertificateRefLocation location) {
		List<CertificateRef> result = new ArrayList<CertificateRef>();
		if (unsignedAttributes != null) {
			Attribute attribute = unsignedAttributes.get(attributeOid);
			if (attribute != null) {
				final ASN1Sequence seq = (ASN1Sequence) attribute.getAttrValues().getObjectAt(0);
				for (int ii = 0; ii < seq.size(); ii++) {
					try {
						OtherCertID otherCertId = OtherCertID.getInstance(seq.getObjectAt(ii));
						DigestAlgorithm digestAlgo = DigestAlgorithm.forOID(otherCertId.getAlgorithmHash().getAlgorithm().getId());
						CertificateRef certRef = new CertificateRef();
						certRef.setCertDigest(new Digest(digestAlgo, otherCertId.getCertHash()));
						IssuerSerial issuerSerial = otherCertId.getIssuerSerial();
						if (issuerSerial != null) {
							certRef.setIssuerInfo(DSSASN1Utils.getIssuerInfo(issuerSerial));
						}
						certRef.setLocation(location);
						result.add(certRef);
					} catch (Exception e) {
						LOG.warn("Unable to parse encapsulated OtherCertID : {}", e.getMessage());
					}
				}
			}
		}
		return result;
	}

}
