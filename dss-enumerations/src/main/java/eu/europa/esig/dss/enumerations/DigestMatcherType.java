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
package eu.europa.esig.dss.enumerations;

/**
 * Defines available types of DigestMatchers (signed data origins)
 */
public enum DigestMatcherType {

	/** XAdES signed reference */
	REFERENCE, 

	/** XAdES signed reference of Object type */
	OBJECT, 

	/** XAdES signed manifest */
	MANIFEST, 

	/** XAdES SignedProperties element */
	SIGNED_PROPERTIES,
	
	/** XAdES KeyInfo element */
	KEY_INFO,

	/** XAdES SignatureProperties element */
	SIGNATURE_PROPERTIES,

	/** XAdES XPointer reference */
	XPOINTER,
	
	/** XAdES and ASiC CAdES */
	MANIFEST_ENTRY,
	
	/** XAdES signed SignatureValue (counter signature) */
	COUNTER_SIGNATURE,

	/** CAdES */
	MESSAGE_DIGEST, 
	
	/** Digest from decrypted content SignatureValue (CAdES/PAdES) */
	CONTENT_DIGEST,
	
	/** 
	 * JAdES Digest on result of concatenation 
	 * ASCII(BASE64URL(UTF8(JWSProtected Header)) || '.' || BASE64URL(JWS Payload)) 
	 */
	JWS_SIGNING_INPUT,
	
	/** JAdES or CB-AdES Detached entry */
	SIG_D_ENTRY,

	/**
	 * COSE Digest on result of serialization of Sig_structure array:
	 * <p>
	 * {@code 
	 * 	Sig_structure = [
	 *     context : "Signature" / "Signature1",
	 *     body_protected : empty_or_serialized_map,
	 *     ? sign_protected : empty_or_serialized_map,
	 *     external_aad : bstr,
	 *     payload : bstr
	 *  ]
	 * }
	 */
	COSE_SIG_STRUCTURE,

	/** Defines the signature value of a master signature signed by a counter signature */
	COUNTER_SIGNED_SIGNATURE_VALUE,

	/** Timestamp */
	MESSAGE_IMPRINT,

	/** Evidence record archive object */
	EVIDENCE_RECORD_ARCHIVE_OBJECT,

	/** Identifies evidence record archive object which has not been associated with any of the provided documents */
	EVIDENCE_RECORD_ORPHAN_REFERENCE,

	/** Evidence record previous archive time-stamp object */
	EVIDENCE_RECORD_ARCHIVE_TIME_STAMP,

	/** Evidence record previous archive time-stamp sequence */
	EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE,

	/** Evidence record embedded in a signature */
	EVIDENCE_RECORD_MASTER_SIGNATURE,

	/** Disclosure attached to a presentation of attestation */
	SELECTIVE_DISCLOSURE,

	/** Disclosure nested to provided disclosure to a presentation of attestation */
	NESTED_SELECTIVE_DISCLOSURE,

	/** Incorporated SD claim for which no matching provided disclosure has been found */
	ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM,

	/** Input used to compute a key binding signature (used in attestation presentation) */
	KEY_BINDING_SIGNATURE

}
