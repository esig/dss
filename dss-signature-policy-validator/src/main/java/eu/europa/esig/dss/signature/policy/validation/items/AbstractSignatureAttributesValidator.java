/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.validation.items;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public abstract class AbstractSignatureAttributesValidator implements ItemValidator {
	
	private List<String> mandatedAttributes = new ArrayList<String>();
	private List<String> missingAttributes = new ArrayList<String>();
	
	public AbstractSignatureAttributesValidator(List<String> mandatedAttributes) {
		super();
		if (mandatedAttributes != null) {
			this.mandatedAttributes.addAll(mandatedAttributes);
		}
	}

	public boolean validate() {
		if (mandatedAttributes.isEmpty()) {
			return true;
		}
		for (String oid : mandatedAttributes) {
			if (containsAttribute(oid)) {
				missingAttributes.add(oid);
			}
		}
		
		return missingAttributes.isEmpty();
	}

	public List<String> getMissingAttributes() {
		return Collections.unmodifiableList(missingAttributes);
	}
	
	@Override
	public String getErrorDetail() {
		return null;
	}

	protected abstract boolean containsAttribute(String oid);
}
