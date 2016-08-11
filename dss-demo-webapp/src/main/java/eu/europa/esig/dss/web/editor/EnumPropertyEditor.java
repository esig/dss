package eu.europa.esig.dss.web.editor;

import java.beans.PropertyEditorSupport;

import eu.europa.esig.dss.utils.Utils;

public class EnumPropertyEditor extends PropertyEditorSupport {

	@SuppressWarnings("rawtypes")
	private Class clazzEnum;

	public EnumPropertyEditor(Class<?> clazzEnum) {
		this.clazzEnum = clazzEnum;
	}

	@Override
	@SuppressWarnings("rawtypes")
	public String getAsText() {
		return getValue() == null ? Utils.EMPTY_STRING : ((Enum) getValue()).name();
	}

	@Override
	@SuppressWarnings("unchecked")
	public void setAsText(String text) throws IllegalArgumentException {
		try {
			setValue(Enum.valueOf(clazzEnum, text));
		} catch (Exception e) {
			setValue(null);
		}
	}

}
