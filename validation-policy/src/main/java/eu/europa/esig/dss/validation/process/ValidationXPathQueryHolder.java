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
package eu.europa.esig.dss.validation.process;

/**
 *
 */
public interface ValidationXPathQueryHolder {

	public static final String XP_REFERENCE_DATA_FOUND = "./BasicSignature/ReferenceDataFound/text()";
	public static final String XP_REFERENCE_DATA_INTACT = "./BasicSignature/ReferenceDataIntact/text()";
	public static final String XP_SIGNATURE_INTACT = "./BasicSignature/SignatureIntact/text()";
	public static final String XP_SIGNATURE_VALID = "./BasicSignature/SignatureValid/text()";

	public static final String XP_MESSAGE_IMPRINT_DATA_FOUND = "./MessageImprintDataFound/text()";
	public static final String XP_MESSAGE_IMPRINT_DATA_INTACT = "./MessageImprintDataIntact/text()";

	public static final String XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/EncryptionAlgoUsedToSignThisToken/text()";
	public static final String XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/DigestAlgoUsedToSignThisToken/text()";
	public static final String XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/KeyLengthUsedToSignThisToken/text()";
}
