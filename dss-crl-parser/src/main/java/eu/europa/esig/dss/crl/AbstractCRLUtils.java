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
package eu.europa.esig.dss.crl;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
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
	
	protected void extractIssuingDistributionPointBinary(CRLValidity validity, byte[] issuingDistributionPointBinary) {
		if (issuingDistributionPointBinary != null) {
			IssuingDistributionPoint issuingDistributionPoint = IssuingDistributionPoint
					.getInstance(ASN1OctetString.getInstance(issuingDistributionPointBinary).getOctets());
			validity.setOnlyAttributeCerts(issuingDistributionPoint.onlyContainsAttributeCerts());
			validity.setOnlyCaCerts(issuingDistributionPoint.onlyContainsCACerts());
			validity.setOnlyUserCerts(issuingDistributionPoint.onlyContainsUserCerts());
			validity.setIndirectCrl(issuingDistributionPoint.isIndirectCRL());
			validity.setReasonFlags(issuingDistributionPoint.getOnlySomeReasons());
			validity.setUrl(getUrl(issuingDistributionPoint.getDistributionPoint()));
		} else {
			LOG.warn("issuingDistributionPointBinary is null. Issuing Distribution Point fields in CRLValidity cannot be filled.");
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
