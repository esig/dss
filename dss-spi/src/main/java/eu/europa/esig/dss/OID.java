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

	/**
	 * id-kp-OCSPSigning Indicates that a X.509 Certificates corresponding private key may be used by an authority to
	 * sign OCSP-Responses
	 */
	public static final ASN1ObjectIdentifier id_kp_OCSPSigning = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.9");

	/**
	 * Certificate extension: "id_ce_extKeyUsage" (Extended key usage)
	 * This field indicates one or more purposes for which the certified public key may be used, in addition to or in
	 * place of the basic purposes indicated in the key usage
	 * extension field.
	 *
	 * More information can be found in Recommendation ITU-T X.509 (March 2000) and in ISO/IEC 9594-8 (2001):
	 * "Directory: Public-key and attribute certificate frameworks".
	 */
	public static final ASN1ObjectIdentifier id_ce_extKeyUsage = new ASN1ObjectIdentifier("2.5.29.37");

	/**
	 * Not defined in: PKCSObjectIdentifiers
	 * mime-type attribute
	 * See ETSI TS 101 733, clause 5.11.5
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_mimeType = new ASN1ObjectIdentifier("0.4.0.1733.2.1");

	public static final ASN1ObjectIdentifier id_etsi_electronicSignatureStandard = new ASN1ObjectIdentifier("0.4.0.1733");

	public static final ASN1ObjectIdentifier id_etsi_electronicSignatureStandard_attributes = id_etsi_electronicSignatureStandard.branch("2");

	/**
	 * id-aa-ets-archiveTimestampV2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
	 * pkcs-9(9) smime(16)
	 * id-aa(2) 48}
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV2 = PKCSObjectIdentifiers.id_aa.branch("48");

	/**
	 * id-aa-ets-archiveTimestampV3 OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0)
	 * electronic-signature-standard(1733)
	 * attributes(2) 4 }
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV3 = id_etsi_electronicSignatureStandard_attributes.branch("4");

	/**
	 * id-aa-ATSHashIndex OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0)
	 * electronicsignature-standard(1733)
	 * attributes(2) 5 }
	 */
	public static final ASN1ObjectIdentifier id_aa_ATSHashIndex = id_etsi_electronicSignatureStandard_attributes.branch("5");

	/**
	 * The CRL extension expiredCertOnCRL.
	 */
	public static final ASN1ObjectIdentifier id_ce_expiredCertsOnCRL = new ASN1ObjectIdentifier("2.5.29.60");

	public static final ASN1ObjectIdentifier icpBrasil_pa_iti = new ASN1ObjectIdentifier("2.16.76.1.7.1");

	public static final ASN1ObjectIdentifier icpBrasil_pa_iti_adrb_pdf = icpBrasil_pa_iti.branch("11");

	public static final ASN1ObjectIdentifier icpBrasil_pa_iti_adrb_pdf_v1 = icpBrasil_pa_iti_adrb_pdf.branch("1");
}
