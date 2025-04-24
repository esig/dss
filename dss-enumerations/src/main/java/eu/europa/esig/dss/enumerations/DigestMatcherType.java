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
	JWS_SIGNING_INPUT_DIGEST,
	
	/** JAdES Detached entry */
	SIG_D_ENTRY,

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
	EVIDENCE_RECORD_MASTER_SIGNATURE

}
