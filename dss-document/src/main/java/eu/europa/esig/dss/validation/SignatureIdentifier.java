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
package eu.europa.esig.dss.validation;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Date;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;

public class SignatureIdentifier extends Identifier {
	
	private static final long serialVersionUID = -6700888325973167656L;

	public static SignatureIdentifier buildSignatureIdentifier(Date signingTime, TokenIdentifier tokenIdentifier, String... customIdentifiers) {
		return buildSignatureIdentifier(signingTime, tokenIdentifier, null, customIdentifiers);
	}

	public static SignatureIdentifier buildSignatureIdentifier(Date signingTime, TokenIdentifier tokenIdentifier, 
			Integer customInteger, String... stringIdentifiers) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (signingTime != null) {
				dos.writeLong(signingTime.getTime());
			}
			if (tokenIdentifier != null) {
				dos.writeChars(tokenIdentifier.asXmlId());
			}
			if (customInteger != null) {
				dos.writeInt(customInteger);
			}
			if (stringIdentifiers != null) {
				for (String str : stringIdentifiers) {
					if (str != null) {
						dos.writeChars(str);
					}
				}
			}
			dos.flush();
			return new SignatureIdentifier(baos.toByteArray());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	SignatureIdentifier(byte[] bytes) {
		super(bytes);
	}

}
