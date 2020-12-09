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
			List<Object> etsiUContent = DSSJsonUtils.getEtsiU(jws); // unmodifiable copy
			if (Utils.isCollectionNotEmpty(etsiUContent)) {
				for (int ii = 0; ii < etsiUContent.size(); ii++) {
					Object item = etsiUContent.get(ii);
					Map<String, Object> map = DSSJsonUtils.parseEtsiUComponent(item);
					if (map != null) {
						// increment a hashCode because equal Strings compute the same hashCode
						Map.Entry<String, Object> mapEntry = map.entrySet().iterator().next();
						EtsiUComponent etsiUComponent = new EtsiUComponent(
								item, mapEntry.getKey(), mapEntry.getValue(), ii);
						components.add(etsiUComponent);
					}
				}
			}
		}
		return components;
	}

	/**
	 * Adds a new entry to the 'etsiU' array
	 * 
	 * @param jws              {@link JWS} to enrich
	 * @param headerName       {@link String} representing the name of the 'etsiU'
	 *                         entry
	 * @param value            represents a value of the 'etsiU' entry
	 * @param base64UrlEncoded defines if the entry shall be incorporated in its
	 *                         corresponding base64url representation
	 */
	public void addComponent(final JWS jws, String headerName, Object value, boolean base64UrlEncoded) {
		List<Object> etsiU = getEtsiUToEdit(jws);
		Object etsiEntry = getComponent(headerName, value, base64UrlEncoded);
		etsiU.add(etsiEntry);
	}

	private Object getComponent(String name, Object value, boolean base64UrlEncoded) {
		JsonObject jsonObject = new JsonObject();
		jsonObject.put(name, value);
		return base64UrlEncoded ? DSSJsonUtils.toBase64Url(jsonObject) : jsonObject;
	}

	/**
	 * Removes the last 'etsiU' item with the given {@code headerName}
	 * 
	 * @param jws        {@link JWS} to modify
	 * @param headerName of the 'etsiU' entry to remove
	 */
	public void removeLastComponent(final JWS jws, String headerName) {
		List<Object> etsiU = getEtsiUToEdit(jws);
		ListIterator<Object> iterator = etsiU.listIterator(etsiU.size());
		while (iterator.hasPrevious()) {
			Object object = iterator.previous();
			Map<String, Object> etsiUComponent = DSSJsonUtils.parseEtsiUComponent(object);
			if (etsiUComponent != null && etsiUComponent.containsKey(headerName)) {
				iterator.remove();
			}
		}
	}

	/**
	 * Replaces the given attribute within the 'etsiU' header array
	 * 
	 * @param jws       {@link JWS} to modify
	 * @param attribute {@link EtsiUComponent} to replace
	 */
	public void replaceComponent(final JWS jws, EtsiUComponent attribute) {
		List<Object> etsiU = getEtsiUToEdit(jws);
		ListIterator<Object> iterator = etsiU.listIterator();
		while (iterator.hasNext()) {
			Object item = iterator.next();
			if (attribute.hashCode() == item.hashCode()) {
				iterator.set(attribute.getComponent());
				break;
			}
		}
	}

	@SuppressWarnings("unchecked")
	private List<Object> getEtsiUToEdit(JWS jws) {
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
