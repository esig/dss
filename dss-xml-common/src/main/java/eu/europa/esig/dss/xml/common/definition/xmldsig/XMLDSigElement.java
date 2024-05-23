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
package eu.europa.esig.dss.xml.common.definition.xmldsig;

import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

/**
 * XMLDSig elements
 *
 */
public enum XMLDSigElement implements DSSElement {

	/** CanonicalizationMethod */
	CANONICALIZATION_METHOD("CanonicalizationMethod"),

	/** DigestMethod */
	DIGEST_METHOD("DigestMethod"),

	/** DigestValue */
	DIGEST_VALUE("DigestValue"),

	/** DSAKeyValue */
	DSA_KEY_VALUE("DSAKeyValue"),

	/** Exponent */
	EXPONENT("Exponent"),

	/** G */
	G("G"),

	/** HMACOutputLength */
	HMAC_OUTPUT_LENGTH("HMACOutputLength"),

	/** J */
	J("J"),

	/** KeyInfo */
	KEY_INFO("KeyInfo"),

	/** KeyName */
	KEY_NAME("KeyName"),

	/** KeyValue */
	KEY_VALUE("KeyValue"),

	/** Manifest */
	MANIFEST("Manifest"),

	/** MgmtData */
	MGMT_DATA("MgmtData"),

	/** Modulus */
	MODULUS("Modulus"),

	/** Object */
	OBJECT("Object"),

	/** P */
	P("P"),

	/** PgenCounter */
	PGEN_COUNTER("PgenCounter"),

	/** PGPData */
	PGP_DATA("PGPData"),

	/** PGPKeyID */
	PGP_KEY_ID("PGPKeyID"),

	/** PGPKeyPacket */
	PGP_KEY_PACKET("PGPKeyPacket"),

	/** Q */
	Q("Q"),

	/** Reference */
	REFERENCE("Reference"),

	/** RetrievalMethod */
	RETRIEVAL_METHOD("RetrievalMethod"),

	/** RSAKeyValue */
	RSA_KEY_VALUE("RSAKeyValue"),

	/** Seed */
	SEED("Seed"),

	/** Signature */
	SIGNATURE("Signature"),

	/** SignatureMethod */
	SIGNATURE_METHOD("SignatureMethod"),

	/** SignatureProperties */
	SIGNATURE_PROPERTIES("SignatureProperties"),

	/** SignatureProperty */
	SIGNATURE_PROPERTY("SignatureProperty"),

	/** SignatureValue */
	SIGNATURE_VALUE("SignatureValue"),

	/** SignedInfo */
	SIGNED_INFO("SignedInfo"),

	/** SPKIData */
	SPKI_DATA("SPKIData"),

	/** SPKISexp */
	SPKI_SEXP("SPKISexp"),

	/** Transform */
	TRANSFORM("Transform"),

	/** Transforms */
	TRANSFORMS("Transforms"),

	/** X509Certificate */
	X509_CERTIFICATE("X509Certificate"),

	/** X509CRL */
	X509_CRL("X509CRL"),

	/** X509Data */
	X509_DATA("X509Data"),

	/** X509IssuerName */
	X509_ISSUER_NAME("X509IssuerName"),

	/** X509IssuerSerial */
	X509_ISSUER_SERIAL("X509IssuerSerial"),

	/** X509SerialNumber */
	X509_SERIAL_NUMBER("X509SerialNumber"),

	/** X509SKI */
	X509_SKI("X509SKI"),

	/** X509SubjectName */
	X509_SUBJECT_NAME("X509SubjectName"),

	/** XPath */
	XPATH("XPath"),

	/** Y */
	Y("Y");

	/** Namespace */
	private final DSSNamespace namespace;

	/** The tag name */
	private final String tagName;

	/**
	 * Default constructor
	 *
	 * @param tagName {@link String}
	 */
	XMLDSigElement(String tagName) {
		this.tagName = tagName;
		this.namespace = XMLDSigNamespace.NS;
	}

	@Override
	public DSSNamespace getNamespace() {
		return namespace;
	}

	@Override
	public String getTagName() {
		return tagName;
	}

	@Override
	public String getURI() {
		return namespace.getUri();
	}

	@Override
	public boolean isSameTagName(String value) {
		return tagName.equals(value);
	}

}
