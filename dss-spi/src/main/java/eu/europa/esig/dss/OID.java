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
package eu.europa.esig.dss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public class OID {

	private OID() {
	}

	/**
	 * id-aa-ets-archiveTimestampV2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
	 * pkcs-9(9) smime(16) id-aa(2) 48}
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV2 = PKCSObjectIdentifiers.id_aa.branch("48");

	public static final ASN1ObjectIdentifier id_etsi_electronicSignatureStandard_attributes = new ASN1ObjectIdentifier("0.4.0.1733.2");

	/**
	 * id-aa-ets-mimeType OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0)
	 * electronic-signature-standard(1733) attributes(2) 1 }
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_mimeType = id_etsi_electronicSignatureStandard_attributes.branch("1");

	/**
	 * id-aa-ets-archiveTimestampV3 OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0)
	 * electronic-signature-standard(1733) attributes(2) 4 }
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV3 = id_etsi_electronicSignatureStandard_attributes.branch("4");

	/**
	 * id-aa-ATSHashIndex OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0)
	 * electronicsignature-standard(1733) attributes(2) 5 }
	 */
	public static final ASN1ObjectIdentifier id_aa_ATSHashIndex = id_etsi_electronicSignatureStandard_attributes.branch("5");

	/**
	 * id-aa-ets-signerAttrV2 OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) cades(19122)
	 * attributes(1) 1 }
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_signerAttrV2 = new ASN1ObjectIdentifier("0.4.0.19122.1.1");

	/**
	 * id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
	 * id-at-role OBJECT IDENTIFIER ::= { id-at 72}
	 */
	public static final ASN1ObjectIdentifier id_at_role = new ASN1ObjectIdentifier("2.5.4.72");

}
