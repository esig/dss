package eu.europa.esig.dss.web.editor;

import java.beans.PropertyEditorSupport;

import org.apache.commons.lang.StringUtils;

public class EnumPropertyEditor extends PropertyEditorSupport {

	@SuppressWarnings("rawtypes")
	private Class clazzEnum;

	public EnumPropertyEditor(Class<?> clazzEnum) {
		this.clazzEnum = clazzEnum;
	}

	@Override
	@SuppressWarnings("rawtypes")
	public String getAsText() {
		return getValue() == null ? StringUtils.EMPTY : ((Enum) getValue()).name();
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
