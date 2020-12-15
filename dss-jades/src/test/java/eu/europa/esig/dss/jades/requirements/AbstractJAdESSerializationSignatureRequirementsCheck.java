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
package eu.europa.esig.dss.jades.requirements;

import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;

public abstract class AbstractJAdESSerializationSignatureRequirementsCheck extends AbstractJAdESRequirementsCheck {
	
	@Override
	protected String getPayload(byte[] byteArray) throws Exception {
		Map<String, Object> jsonMap = JsonUtil.parseJson(new String(byteArray));
		return (String) jsonMap.get("payload");
	}
	
	@Override
	protected String getProtectedHeader(byte[] byteArray) throws Exception {
		Map<?, ?> signature = getSignature(byteArray);
		return (String) signature.get("protected");
	}
	
	@Override
	protected String getSignatureValue(byte[] byteArray) throws Exception {
		Map<?, ?> signature = getSignature(byteArray);
		return (String) signature.get("signature");
	}
	
	@Override
	protected Map<?, ?> getUnprotectedHeader(byte[] byteArray) throws Exception {
		Map<?, ?> signature = getSignature(byteArray);
		return (Map<?, ?>) signature.get("header");
	}
	
	private Map<?, ?> getSignature(byte[] byteArray) throws Exception {
		Map<String, Object> jsonMap = JsonUtil.parseJson(new String(byteArray));
		List<?> signaturesList = (List<?>) jsonMap.get("signatures");
		return (Map<?, ?>) signaturesList.get(0);
	}

}
