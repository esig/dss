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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JsonObject;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureProperties;
import org.jose4j.json.internal.json_simple.JSONArray;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

/**
 * Represents the list of components present inside the unprotected 'etsiU' header
 *
 */
public class JAdESEtsiUHeader implements SignatureProperties<EtsiUComponent> {

	/** The JWS signature */
	private final JWS jws;

	/** The list of 'etsiU' components */
	private List<EtsiUComponent> components;

	/**
	 * The default constructor
	 *
	 * @param jws {@link JWS} signature
	 */
	public JAdESEtsiUHeader(JWS jws) {
		this.jws = jws;
	}

	@Override
	public boolean isExist() {
		return Utils.isCollectionNotEmpty(getAttributes());
	}

	@Override
	public List<EtsiUComponent> getAttributes() {
		if (components == null) {
			components = new ArrayList<>();
			List<Object> etsiUContent = DSSJsonUtils.getEtsiU(jws);
			if (Utils.isCollectionNotEmpty(etsiUContent)) {
				for (int ii = 0; ii < etsiUContent.size(); ii++) {
					Object item = etsiUContent.get(ii);
					EtsiUComponent etsiUComponent = EtsiUComponent.build(item, ii);
					if (etsiUComponent != null) {
						components.add(etsiUComponent);
					}
					// else : unable to create, skip
				}
			}
		}
		return components;
	}

	/**
	 * Adds a new entry to the 'etsiU' array
	 *
	 * @param headerName       {@link String} representing the name of the 'etsiU'
	 *                         entry
	 * @param value            represents a value of the 'etsiU' entry
	 * @param base64UrlEncoded defines if the entry shall be incorporated in its
	 *                         corresponding base64url representation
	 */
	public void addComponent(String headerName, Object value, boolean base64UrlEncoded) {
		List<Object> etsiU = getEtsiUToEdit();
		Object etsiEntry = getComponent(headerName, value, base64UrlEncoded);
		etsiU.add(etsiEntry);
	}

	private Object getComponent(String name, Object value, boolean base64UrlEncoded) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.put(name, value);
		return base64UrlEncoded ? DSSJsonUtils.toBase64Url(jsonObject) : jsonObject;
	}

	/**
	 * Removes the 'etsiU' components with the given {@code headerName}
	 *
	 * @param headerName of the 'etsiU' entry to remove
	 */
	public void removeComponent(String headerName) {
		List<Object> etsiU = getEtsiUToEdit();
		if (Utils.isCollectionNotEmpty(etsiU)) {
			ListIterator<Object> iterator = getBackwardIterator(etsiU);
			while (iterator.hasPrevious()) {
				removeLastIfMatches(iterator, headerName);
			}
		}
	}

	/**
	 * Removes the last 'etsiU' item if the name matches to the given {@code headerName}
	 *
	 * @param headerName of the 'etsiU' entry to remove
	 */
	public void removeLastComponent(String headerName) {
		List<Object> etsiU = getEtsiUToEdit();
		if (Utils.isCollectionNotEmpty(etsiU)) {
			ListIterator<Object> iterator = getBackwardIterator(etsiU);
			removeLastIfMatches(iterator, headerName);
		}
	}

	private ListIterator<Object> getBackwardIterator(List<Object> etsiU) {
		return etsiU.listIterator(etsiU.size());
	}

	private void removeLastIfMatches(ListIterator<?> iterator, String headerName) {
		Object object = iterator.previous();
		Map<String, Object> etsiUComponent = DSSJsonUtils.parseEtsiUComponent(object);
		if (etsiUComponent != null && etsiUComponent.containsKey(headerName)) {
			iterator.remove();
		}
	}

	/**
	 * Replaces the given attribute within the 'etsiU' header array
	 *
	 * @param attribute {@link EtsiUComponent} to replace
	 */
	public void replaceComponent(EtsiUComponent attribute) {
		List<Object> etsiU = getEtsiUToEdit();
		ListIterator<Object> iterator = etsiU.listIterator();
		while (iterator.hasNext()) {
			int position = iterator.nextIndex();
			Object item = iterator.next();
			EtsiUComponent currentComponent = EtsiUComponent.build(item, position);
			if (attribute.getIdentifier().equals(currentComponent.getIdentifier())) {
				iterator.set(attribute.getComponent());
				break;
			}
		}
	}

	@SuppressWarnings("unchecked")
	private List<Object> getEtsiUToEdit() {
		Map<String, Object> unprotected = jws.getUnprotected();
		if (unprotected == null) {
			unprotected = new HashMap<>();
			jws.setUnprotected(unprotected);
		}
		clearCachedAttributes();
		return (List<Object>) unprotected.computeIfAbsent(JAdESHeaderParameterNames.ETSI_U, k -> new JSONArray());
	}

	private void clearCachedAttributes() {
		this.components = null;
	}

}
