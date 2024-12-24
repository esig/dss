/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * Contains the used OIDs
 */
public class OID {

	private OID() {
		// empty
	}

	/**
	 * id-aa-ets-archiveTimestampV2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
	 * pkcs-9(9) smime(16) id-aa(2) 48}
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV2 = PKCSObjectIdentifiers.id_aa.branch("48");

	/**
	 * Attributes {itu-t(0) identified-organization(4) etsi(0) electronic-signature-standard(1733) attributes(2)}
	 */
	public static final ASN1ObjectIdentifier id_etsi_electronicSignatureStandard_attributes = new ASN1ObjectIdentifier("0.4.0.1733.2");

	/**
	 * Signer attributes {itu-t(0) identified-organization(4) etsi(0) cades(19122) attributes(1)} (see ETSI EN 319 122-1)
	 */
	public static final ASN1ObjectIdentifier id_etsi_signer_attributes = new ASN1ObjectIdentifier("0.4.0.19122.1");

	/**
	 * Signer attributes {itu-t(0) identified-organization(4) etsi(0) cades(19122) id-spq (2)} (see ETSI EN 319 122-1)
	 */
	public static final ASN1ObjectIdentifier id_etsi_spq = new ASN1ObjectIdentifier("0.4.0.19122.2");

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
	 * id-aa-ets-signerAttrV2 OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) 
	 * etsi(0) cades(19122) attributes(1) 1 }
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_signerAttrV2 = id_etsi_signer_attributes.branch("1");

	/**
	 * id-aa-ets-sigPolicyStore OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) 
	 * etsi(0) cades(19122) attributes(1) 3 }
	 */
	public static final ASN1ObjectIdentifier id_aa_ets_sigPolicyStore = id_etsi_signer_attributes.branch("3");

	/**
	 * id-aa-ATSHashIndex-v2 OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4)
     * etsi(0) cades(19122) attributes(1) 4 } 
	 */
	public static final ASN1ObjectIdentifier id_aa_ATSHashIndexV2 = id_etsi_signer_attributes.branch("4");

	/**
	 * id-aa-ATSHashIndex-v3 OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4)
     * etsi(0) cades(19122) attributes(1) 5 } 
	 */
	public static final ASN1ObjectIdentifier id_aa_ATSHashIndexV3 = id_etsi_signer_attributes.branch("5");

	/**
	 * id-spq-ets-docspec OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4)
	 * etsi(0) cades(19122) id-spq (2) 1 }
	 */
	public static final ASN1ObjectIdentifier id_sp_doc_specification = id_etsi_spq.branch("1");

	/**
	 * id-aa-ets-attrCertificateRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
	 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 44 }
	 */
	public static final ASN1ObjectIdentifier attributeCertificateRefsOid = PKCSObjectIdentifiers.id_aa.branch("44");

	/**
	 * id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
	 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 45} 
	 */
	public static final ASN1ObjectIdentifier attributeRevocationRefsOid = PKCSObjectIdentifiers.id_aa.branch("45");

	/**
	 * id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
	 * id-at-role OBJECT IDENTIFIER ::= { id-at 72}
	 */
	public static final ASN1ObjectIdentifier id_at_role = new ASN1ObjectIdentifier("2.5.4.72");

	/**
	 * Defined as adbe-revocationInfoArchival {adbe(1.2.840.113583) acrobat(1)
	 * security(1) 8} in "PDF Reference, fifth edition: Adobe® Portable Document
	 * Format, Version 1.6" Adobe Systems Incorporated, 2004.
	 */
	public static final ASN1ObjectIdentifier adbe_revocationInfoArchival = new ASN1ObjectIdentifier(
			"1.2.840.113583.1.1.8");

	// --- ETSI TS 119 495 V1.4.1

	/**
	 * etsi-psd2-qcStatement QC-STATEMENT ::= {SYNTAX PSD2QcType IDENTIFIED BY
	 * id-etsi-psd2-qcStatement }
	 * 
	 * id-etsi-psd2-qcStatement OBJECT IDENTIFIER ::={itu-t(0)
	 * identified-organization(4) etsi(0) psd2(19495) qcstatement(2) }
	 */
	public static final ASN1ObjectIdentifier psd2_qcStatement = new ASN1ObjectIdentifier("0.4.0.19495.2");

	/**
	 * esi4-qcStatement-7 QC-STATEMENT ::= { SYNTAX QcCClegislation IDENTIFIED BY id-etsi-qcsQcCClegislation }
	 * id-etsi-qcs-QcCClegislation OBJECT IDENTIFIER ::= { id-etsi-qcs 7 }
	 */
	public static final ASN1ObjectIdentifier id_etsi_qcs_QcCClegislation = new ASN1ObjectIdentifier("0.4.0.1862.1.7");

	/**
	 * EN 319 412-1 "5.2.2 Validity Assured - Short Term"
	 *
	 * id-etsi-ext OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) id-cert-profile(194121) 2 }
	 * id-etsi-ext-valassured-ST-certs OBJECT IDENTIFIER ::= { id-etsi-ext 1 }
	 */
	public static final ASN1ObjectIdentifier id_etsi_ext_valassured_ST_certs = new ASN1ObjectIdentifier("0.4.0.194121.2.1");

	/**
	 * ASN.1 Internal EvidenceRecord Attribute
	 * id-aa-er-internal  OBJECT IDENTIFIER ::= { iso(1) member-body(2)
	 * us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) id-aa(2) 49 }
	 */
	public static final ASN1ObjectIdentifier id_aa_er_internal = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.49");
	/**
	 * ASN.1 External EvidenceRecord Attribute
	 * id-aa-er-external  OBJECT IDENTIFIER ::= { iso(1) member-body(2)
	 * us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) id-aa(2) 50 }
	 */
	public static final ASN1ObjectIdentifier id_aa_er_external = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.50");

}
