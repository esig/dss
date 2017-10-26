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
package eu.europa.esig.dss.cades.signerattributesV2;

import java.util.List;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import eu.europa.esig.dss.BLevelParameters;

public class SignerAttributeV2Factory {

	public static SignerAttributeV2 getSignerAttributeV2(BLevelParameters blvl, String id) {

		SignerAttributeV2.SignerAttributeV2Builder builder = SignerAttributeV2.builder();

		final List<String> claimedSignerRoles = blvl.getClaimedSignerRoles();

		if (claimedSignerRoles != null) {

			for (final String claimedSignerRole : claimedSignerRoles) {

				final DERUTF8String roles = new DERUTF8String(claimedSignerRole);

				// TODO: role attribute key (id_at_name) should be customizable
				final org.bouncycastle.asn1.x509.Attribute id_aa_ets_signerAttr = new org.bouncycastle.asn1.x509.Attribute(X509ObjectIdentifiers.id_at_name,
						new DERSet(roles));
				builder.addClaimedAttribute(id_aa_ets_signerAttr);
			}
		}

		// TODO: CertifiedAttributesV2: final List<String> certifiedSignerRoles = blvl.getCertifiedSignerRoles();

		final List<String> signedAssertions = blvl.getSignedAssertions();

		if (signedAssertions != null) {

			for (final String signedAssertion : signedAssertions) {

				SignedAssertion sa = new SignedAssertion(id, signedAssertion);
				builder.addSignedAssertion(sa);
			}
		}
		return builder.build();
	}
}
