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
package eu.europa.esig.dss.tsl.job;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;

import java.util.List;
import java.util.Map;

public class MockDataLoader implements DataLoader {

	private static final long serialVersionUID = 4624853984865942793L;
	
	private Map<String, DSSDocument> dataMap;
	
	public MockDataLoader(Map<String, DSSDocument> dataMap) {
		this.dataMap = dataMap;
	}

	@Override
	public byte[] get(String url) {
		DSSDocument dssDocument = dataMap.get(url);
		if (dssDocument != null) {
			return DSSUtils.toByteArray(dssDocument);
		}
		return null;
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	@Deprecated
	public byte[] get(String url, boolean refresh) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] post(String url, byte[] content) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setContentType(String contentType) {
		// TODO Auto-generated method stub
		
	}
	
}