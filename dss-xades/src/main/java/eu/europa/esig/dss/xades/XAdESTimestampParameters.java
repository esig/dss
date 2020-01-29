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
package eu.europa.esig.dss.xades;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampParameters;

@SuppressWarnings("serial")
public class XAdESTimestampParameters extends TimestampParameters {

	/**
	 * This is the default canonicalization method for XMLDSIG used for timestamps. Another complication arises because
	 * of the way that the default canonicalization algorithm
	 * handles namespace declarations; frequently a signed XML document needs to be embedded in another document; in
	 * this case the original canonicalization algorithm will not
	 * yield the same result as if the document is treated alone. For this reason, the so-called Exclusive
	 * Canonicalization, which serializes XML namespace declarations
	 * independently of the surrounding XML, was created.
	 */
	private String canonicalizationMethod = CanonicalizationMethod.EXCLUSIVE;
	
	public XAdESTimestampParameters() {
	}
	
	public XAdESTimestampParameters(DigestAlgorithm digestAlgorithm) {
		super(digestAlgorithm);
	}
	
	public XAdESTimestampParameters(DigestAlgorithm digestAlgorithm, String canonicalizationMethod) {
		super(digestAlgorithm);
		this.canonicalizationMethod = canonicalizationMethod;
	}

	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	public void setCanonicalizationMethod(final String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = (prime * result) + ((canonicalizationMethod == null) ? 0 : canonicalizationMethod.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}
		XAdESTimestampParameters other = (XAdESTimestampParameters) obj;
		if (canonicalizationMethod == null) {
			if (other.canonicalizationMethod != null) {
				return false;
			}
		} else if (!canonicalizationMethod.equals(other.canonicalizationMethod)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "TimestampParameters {digestAlgorithm=" + digestAlgorithm.getName() + ", canonicalizationMethod=" + canonicalizationMethod + "}";
	}

}
