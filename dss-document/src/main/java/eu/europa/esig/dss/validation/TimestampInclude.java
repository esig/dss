// TODO-Vin (12/09/2014): CopyRight to be added!
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

/**
 * This class represents
 */
public class TimestampInclude {

    private String uri;
	// TODO-Vin (12/09/2014): What does it mean?
	private boolean referencedData;

	// TODO-Vin (12/09/2014): Is this constructor useful? Does it make sens?
	public TimestampInclude() {}

	// TODO-Vin (12/09/2014): Comments!
	public TimestampInclude(String uri, String referencedData) {
		this.uri = uri;
		this.referencedData = Boolean.parseBoolean(referencedData);
	}

	// TODO-Vin (12/09/2014): Comments!
    public TimestampInclude(String uri, boolean referencedData) {
        this.uri = uri;
        this.referencedData = referencedData;
    }

    public String getURI() {
        return uri;
    }

    public void setURI(String uri) {
        this.uri = uri;
    }


    public boolean isReferencedData() {
        return referencedData;
    }

	// TODO-Vin (12/09/2014): Never used???
	public void setReferencedData(boolean referencedData) {
        this.referencedData = referencedData;
    }
}
