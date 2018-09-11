package eu.europa.esig.dss.crl;

import java.util.Collection;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractCRLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractCRLUtils.class);

	protected void extractExpiredCertsOnCRL(CRLValidity validity, byte[] expiredCertsOnCRLBinaries) {
		if (expiredCertsOnCRLBinaries != null) {
			try {
				ASN1OctetString octetString = (ASN1OctetString) ASN1Primitive.fromByteArray(expiredCertsOnCRLBinaries);
				Time time = Time.getInstance(ASN1Primitive.fromByteArray(octetString.getOctets()));
				if (time != null && time.toASN1Primitive() instanceof ASN1GeneralizedTime) {
					validity.setExpiredCertsOnCRL(time.getDate());
				} else {
					LOG.warn("Attribute 'expiredCertsOnCRL' found but ignored (should be encoded as ASN.1 GeneralizedTime)");
				}
			} catch (Exception e) {
				LOG.error("Unable to parse expiredCertsOnCRL on CRL : " + e.getMessage(), e);
			}
		}
	}

	protected void checkCriticalExtensions(CRLValidity validity, Collection<String> criticalExtensionsOid, byte[] issuingDistributionPointBinary) {
		if (criticalExtensionsOid == null || criticalExtensionsOid.isEmpty()) {
			validity.setUnknownCriticalExtension(false);
		} else {
			IssuingDistributionPoint issuingDistributionPoint = IssuingDistributionPoint
					.getInstance(ASN1OctetString.getInstance(issuingDistributionPointBinary).getOctets());
			final boolean onlyAttributeCerts = issuingDistributionPoint.onlyContainsAttributeCerts();
			final boolean onlyCaCerts = issuingDistributionPoint.onlyContainsCACerts();
			final boolean onlyUserCerts = issuingDistributionPoint.onlyContainsUserCerts();
			final boolean indirectCrl = issuingDistributionPoint.isIndirectCRL();
			ReasonFlags onlySomeReasons = issuingDistributionPoint.getOnlySomeReasons();
			final String url = getUrl(issuingDistributionPoint.getDistributionPoint());
			validity.setUrl(url);
			final boolean urlFound = url != null;
			if (!(onlyAttributeCerts && onlyCaCerts && onlyUserCerts && indirectCrl) && (onlySomeReasons == null) && urlFound) {
				validity.setUnknownCriticalExtension(false);
			}
		}
	}

	private String getUrl(DistributionPointName distributionPoint) {
		if ((distributionPoint != null) && (DistributionPointName.FULL_NAME == distributionPoint.getType())) {
			final GeneralNames generalNames = (GeneralNames) distributionPoint.getName();
			if ((generalNames != null) && (generalNames.getNames() != null && generalNames.getNames().length > 0)) {
				for (GeneralName generalName : generalNames.getNames()) {
					if (GeneralName.uniformResourceIdentifier == generalName.getTagNo()) {
						ASN1String str = (ASN1String) ((DERTaggedObject) generalName.toASN1Primitive()).getObject();
						return str.getString();
					}
				}
			}
		}
		return null;
	}

}
