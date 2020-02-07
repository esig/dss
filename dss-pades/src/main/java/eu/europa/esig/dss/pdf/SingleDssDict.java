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
package eu.europa.esig.dss.pdf;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;

/**
 * This class is a representation of a DSS (Document Security Store) Dictionary embedded in a PDF file.
 * The dictionary is unique in a PDF file and can contain : VRI dictionary, certificates (Certs), OCSP responses (OCSPs)
 * and CRLs.
 * This dictionary is filled in PAdES-BASELINE-LT extension process.
 */
public class SingleDssDict extends AbstractPdfDssDict {

	private static final Logger LOG = LoggerFactory.getLogger(SingleDssDict.class);

	private List<PdfVRIDict> vris;

	public static SingleDssDict extract(PdfDict documentDict) {
		if (documentDict != null) {
			final PdfDict dssCatalog = documentDict.getAsDict(PAdESConstants.DSS_DICTIONARY_NAME);
			if (dssCatalog != null) {
				return new SingleDssDict(dssCatalog);
			}
		}
		LOG.debug("No DSS dictionary found");
		return null;
	}

	protected SingleDssDict(PdfDict dssDictionary) {
		super(dssDictionary);
		readVRI(dssDictionary);
	}

	private void readVRI(PdfDict dssDictionary) {
		PdfDict vriDict = dssDictionary.getAsDict(PAdESConstants.VRI_DICTIONARY_NAME);
		if (vriDict != null) {
			LOG.debug("There is a VRI dictionary in DSS dictionary");
			try {
				String[] names = vriDict.list();
				if (Utils.isArrayNotEmpty(names)) {
					vris = new ArrayList<>();
					for (String name : names) {
						vris.add(new PdfVRIDict(name, vriDict.getAsDict(name)));
					}
				}
			} catch (Exception e) {
				LOG.debug("Unable to analyse VRI dictionary : {}", e.getMessage());
			}
		} else {
			LOG.debug("No VRI dictionary found in DSS dictionary");
		}
	}
	
	@Override
	protected String getDictionaryName() {
		return PAdESConstants.DSS_DICTIONARY_NAME;
	}
	
	@Override
	protected String getCertArrayDictionaryName() {
		return PAdESConstants.CERT_ARRAY_NAME_DSS;
	}
	
	@Override
	protected String getCRLArrayDictionaryName() {
		return PAdESConstants.CRL_ARRAY_NAME_DSS;
	}
	
	@Override
	protected String getOCSPArrayDictionaryName() {
		return PAdESConstants.OCSP_ARRAY_NAME_DSS;
	}

	@Override
	public List<PdfVRIDict> getVRIs() {
		return vris;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		if (vris != null) {
			result = prime * result + vris.hashCode();
		}
		return result;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SingleDssDict other = (SingleDssDict) obj;
		if (vris == null) {
			if (other.vris != null) {
				return false;
			}
		} else if (!vris.equals(other.vris)) {
			return false;
		}
		return true;
	}

}
